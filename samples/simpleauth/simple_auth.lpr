program simple_auth;

{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils,
  Classes,
  fpjson,
  jsonparser,
  DateUtils,
  syncobjs,
  AdvancedHTTPServer;

type
  TSessionStore = class
  private
    FSessions: TStringList; // session_id = username
    FLock: TCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;
    function CreateSession(const Username: string): string;
    function GetUsername(const SessionID: string): string;
    procedure DestroySession(const SessionID: string);
  end;

var
  Sessions: TSessionStore;

  // === Реализация сессий ===
  constructor TSessionStore.Create;
  begin
    inherited Create;
    FSessions := TStringList.Create;
    FSessions.CaseSensitive := False;
    FLock := TCriticalSection.Create;
  end;

  destructor TSessionStore.Destroy;
  begin
    FSessions.Free;
    FLock.Free;
    inherited Destroy;
  end;

  function TSessionStore.CreateSession(const Username: string): string;
  begin
    Result := IntToHex(Random(MaxInt), 8) + IntToHex(Random(MaxInt), 8);
    FLock.Enter;
    try
      FSessions.Values[Result] := Username;
    finally
      FLock.Leave;
    end;
  end;

  function TSessionStore.GetUsername(const SessionID: string): string;
  begin
    FLock.Enter;
    try
      Result := FSessions.Values[SessionID];
    finally
      FLock.Leave;
    end;
  end;

  procedure TSessionStore.DestroySession(const SessionID: string);
  begin
    FLock.Enter;
    try
      FSessions.Delete(FSessions.IndexOfName(SessionID));
    finally
      FLock.Leave;
    end;
  end;

  // === Вспомогательные функции ===
  function GetSessionID(R: TRequest): string;
  begin
    Result := R.CookieValue('session_id');
  end;

  function IsAuthenticated(R: TRequest): boolean;
  var
    SID: string;
  begin
    SID := GetSessionID(R);
    Result := (SID <> '') and (Sessions.GetUsername(SID) <> '');
  end;

  function CurrentUser(R: TRequest): string;
  begin
    Result := Sessions.GetUsername(GetSessionID(R));
  end;

  // === Обработчики ===

  function LoggingMiddleware(Next: THandlerFunc): THandlerFunc;
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    var
      StartTime: TDateTime;
      Duration: int64;
      Proto: string;
    begin
      StartTime := Now;
      if R.TLS then  Proto := 'HTTPS'
      else
        Proto := 'HTTP';
      WriteLn(FormatDateTime('[yyyy-mm-dd hh:nn:ss]', StartTime), ' ',
      Proto, ' ', R.Method, ' ', R.Path, ' from ', R.RemoteAddr);
      Next(W, R);  // Вызываем следующий обработчик

      Duration := MilliSecondsBetween(Now, StartTime);
      WriteLn('  Completed in ', Duration, 'ms');
    end;

  end;

  function RecoveryMiddleware(Next: THandlerFunc): THandlerFunc;
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    begin
      try
        Next(W, R);
      except
        on E: Exception do
        begin
          WriteLn('PANIC: ', E.Message);
          if not W.HeadersSent then
          begin
            W.Header.SetValue('Content-Type', 'text/plain');
            W.WriteHeader(500);
            W.Write('500 Internal Server Error'#13#10);
            W.Write('The server encountered an error and could not complete your request.');
          end;
        end;
      end;
    end;

  end;


  procedure LoginHandler(W: TResponseWriter; R: TRequest);
  var
    Username, Password: string;
    SID: string;
  begin
    if R.Method = 'GET' then
    begin
      W.Header.SetValue('Content-Type', 'text/html; charset=utf-8');
      W.Write('<html><body>' + '<h2>Login</h2>' + '<form method="post">' +
        '  <input name="username" placeholder="Username" required><br><br>' +
        '  <input name="password" type="password" placeholder="Password" required><br><br>'
        +
        '  <button type="submit">Login</button>' + '</form>' + '</body></html>');
      Exit;
    end;

    Username := R.PostFormValue('username');
    Password := R.PostFormValue('password');

    if (Username = 'admin') and (Password = 'secret') then
    begin
      SID := Sessions.CreateSession(Username);

      // устанавливаем cookie
      W.SetCookie('session_id', SID, '/', '', 0, 3600, R.TLS, True, ssLax);

      W.Header.SetValue('Location', '/profile');
      W.WriteHeader(302);
    end
    else
    begin
      W.WriteHeader(401);
      W.Write('Invalid credentials. <a href="/login">Try again</a>');
    end;
  end;

  procedure ProfileHandler(W: TResponseWriter; R: TRequest);
  begin
    if not IsAuthenticated(R) then
    begin
      W.Header.SetValue('Location', '/login');
      W.WriteHeader(302);
      Exit;
    end;

    W.Header.SetValue('Content-Type', 'text/html; charset=utf-8');
    W.Write('<html><body>' + '<h1>Welcome, ' + CurrentUser(R) +
      '!</h1>' + '<p>You are logged in.</p>' + '<a href="/logout">Logout</a>' +
      '</body></html>');
  end;

  procedure LogoutHandler(W: TResponseWriter; R: TRequest);
  var
    SID: string;
  begin
    SID := GetSessionID(R);
    if SID <> '' then
      Sessions.DestroySession(SID);

    // Удаляем куку
    W.SetCookie('session_id', '', '/', '', 0, 0, R.TLS, True, ssLax);

    W.Header.SetValue('Location', '/login');
    W.WriteHeader(302);
  end;

  // === Middleware: защита маршрутов ===
  function AuthMiddleware(Next: THandlerFunc): THandlerFunc;
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    begin
      if not IsAuthenticated(R) then
      begin
        W.Header.SetValue('Location', '/login');
        W.WriteHeader(302);
        Exit;
      end;
      Next(W, R);
    end;

  end;

  // === Главная программа ===
var
  Srv: THTTPServer;
begin
  Randomize;
  Sessions := TSessionStore.Create;

  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);

    Srv.HandleFunc('/login', @LoginHandler);
    Srv.HandleFunc('/logout', @LogoutHandler);

    // Защищённые маршруты
    Srv.HandleFunc('/profile', AuthMiddleware(@ProfileHandler));

    WriteLn('Auth example running on http://localhost:8080');
    WriteLn('Login: admin / secret');
    //Srv.ListenAndServe(':8080');
    Srv.ListenAndServeTLS(':8443', 'server.crt', 'server.key');
  finally
    Sessions.Free;
    Srv.Free;
  end;
end.
