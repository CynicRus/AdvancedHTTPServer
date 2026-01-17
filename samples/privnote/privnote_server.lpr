program PrivNote_Server;

{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}Classes,
  SysUtils,
  fpjson,
  jsonparser,
  DateUtils,
  syncobjs,
  AdvancedHTTPServer,
  NoteStorage;

type
  TCleanupThread = class(TThread)
  protected
    procedure Execute; override;
  end;

var
  CurrNoteStorage: INoteStorage;
  CleanupRunning: boolean = True;

  procedure TCleanupThread.Execute;
  begin
    while CleanupRunning do
    begin
      Sleep(60000); // раз в минуту
      CurrNoteStorage.CleanupExpired;
    end;
  end;

  // === API Handlers ===

  procedure CreateNoteHandler(W: TResponseWriter; R: TRequest);
  var
    JSON: TJSONObject;
    EncryptedData: string;
    ExpireInSec: integer;
    NoteID: string;
  begin
    try
      JSON := GetJSON(R.Body) as TJSONObject;
      EncryptedData := JSON.Get('data', '');
      ExpireInSec := JSON.Get('expire', 3600); // по умолчанию — 1 час

      if EncryptedData = '' then
      begin
        W.WriteHeader(400);
        W.Write('{"error":"Missing data"}');
        Exit;
      end;

      // Ограничиваем максимум (например, 24 часа)
      if ExpireInSec > 86400 then ExpireInSec := 86400;

      NoteID := CurrNoteStorage.CreateNote(EncryptedData, 1, ExpireInSec);
      W.Header.SetValue('Content-Type', 'application/json');
      W.Write('{"id":"' + NoteID + '"}');
    except
      W.WriteHeader(400);
      W.Write('{"error":"Invalid JSON"}');
    end;
  end;

  procedure NotePageHandler(W: TResponseWriter; R: TRequest);
  begin
    W.Header.SetValue('Content-Type', 'text/html; charset=utf-8');
    ServeFile(W, R, 'frontend/view.html');
  end;

  procedure GetNoteHandler(W: TResponseWriter; R: TRequest);
  var
    NoteID: string;
    Note: TNote;
  const
    Prefix = '/api/n/';
  begin
    if Pos(Prefix, R.Path) <> 1 then
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Bad path"}');
      Exit;
    end;

    NoteID := Copy(R.Path, Length(Prefix) + 1, MaxInt); // '/n/abc' -> 'abc'

    if (NoteID = '') then
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Missing id"}');
      Exit;
    end;

    if CurrNoteStorage.GetNote(NoteID, Note) then
    begin
      if Now > Note.ExpiresAt then
      begin
        CurrNoteStorage.DeleteNote(NoteID);
        W.WriteHeader(410);
        W.Write('{"error":"Note expired"}');
        Exit;
      end;

      CurrNoteStorage.DeleteNote(NoteID);

      W.Header.SetValue('Content-Type', 'application/json');
      W.Write('{"data":"' + Note.EncryptedData + '"}');
    end
    else
    begin
      W.WriteHeader(404);
      W.Write('{"error":"Note not found or already read"}');
    end;
  end;

  // === Статика ===
  function LoadFile(const Path: string): string;
  var
    SL: TStringList;
  begin
    Result := '';
    if not FileExists(Path) then Exit;
    SL := TStringList.Create;
    try
      SL.LoadFromFile(Path);
      Result := SL.Text;
    finally
      SL.Free;
    end;
  end;

  procedure StaticHandler(W: TResponseWriter; R: TRequest);
  var
    FilePath: string;
    ContentType: string;
  begin
    if R.Path = '/' then
      FilePath := 'frontend/index.html'
    else if R.Path = '/view' then
      FilePath := 'frontend/view.html'
    else
      FilePath := 'frontend' + R.Path;

    if not FileExists(FilePath) then
    begin
      W.WriteHeader(404);
      W.Write('Not found');
      Exit;
    end;

    case LowerCase(ExtractFileExt(FilePath)) of
      '.html': ContentType := 'text/html';
      '.js': ContentType := 'application/javascript';
      '.css': ContentType := 'text/css';
      else
        ContentType := 'application/octet-stream';
    end;

    W.Header.SetValue('Content-Type', ContentType);
    ServeFile(W, R, FilePath);
  end;

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

  // === Main ===
var
  Srv: THTTPServer;
  CleanupThread: TCleanupThread;
begin
  CurrNoteStorage := TSQLiteNoteStorage.Create('notes.db');
  CleanupThread := TCleanupThread.Create(False);

  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);

    Srv.HandleFunc('/api/note', @CreateNoteHandler); // POST
    Srv.HandleFunc('/api/n/', @GetNoteHandler);    // GET /api/n/<id> (API)

    Srv.HandleFunc('/n/', @NotePageHandler);   // GET /n/<id> (HTML page)

    Srv.HandleFunc('/', @StaticHandler);
    Srv.HandleFunc('/view', @StaticHandler);
    Srv.HandleFunc('/style.css', @StaticHandler);

    WriteLn('PrivNote Server started on http://localhost:3000');
    Srv.ListenAndServe(':3000');
  finally
    CleanupRunning := False;
    CleanupThread.WaitFor;
    CleanupThread.Free;
    CurrNoteStorage.Free;
    Srv.Free;
  end;
end.
