program noteflow_server;

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
  sqlite3dyn,
  sqlite3conn,
  syncobjs,
  DateUtils,
  AdvancedHTTPServer,
  patched_openssl,
  ctypes;

// === Хэширование пароля (простой SHA256 + salt) ===
function HashPassword(const Password, Salt: string): string;
var
  CTX: PEVP_MD_CTX;
  Digest: array[0..63] of byte;
  Len: cuint;
  Input: ansistring;
  I: integer;
begin
  EVP_sha256;
  CTX := EVP_MD_CTX_create();
  Input := ansistring(Password + Salt);
  EVP_DigestInit(CTX, EVP_sha256());
  EVP_DigestUpdate(CTX, @Input[1], Length(Input));
  EVP_DigestFinal(CTX, @Digest, @Len);
  EVP_MD_CTX_free(CTX);
  Result := '';
  for i := 0 to Len - 1 do
    Result := Result + IntToHex(Digest[I], 2);
end;

function GenerateSalt: string;
begin
  Result := IntToHex(Random(MaxInt), 8) + IntToHex(Random(MaxInt), 8);
end;

// === Работа с БД ===
type
  TUserDB = class
  private
    FDB: Psqlite3;
    FLock: TCriticalSection;
    procedure InitDB;
  public
    constructor Create(const FileName: string);
    destructor Destroy; override;
    function RegisterUser(const Username, Password: string): boolean;
    function Authenticate(const Username, Password: string;
      out UserID: integer): boolean;
    procedure SaveNote(const UserID: integer; const Title, Content: string);
    procedure UpdateNote(const UserID, NoteID: integer; const Title, Content: string);
    procedure DeleteNote(const UserID, NoteID: integer);
    procedure GetNotes(const UserID: integer; out Notes: TJSONArray);
  end;

constructor TUserDB.Create(const FileName: string);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  InitialiseSQLite;
  FDB := nil;
  if sqlite3_open(pansichar(ansistring(FileName)), @FDB) <> SQLITE_OK then
    raise Exception.Create('Cannot open database: ' + sqlite3_errmsg(FDB));
  InitDB;
end;

destructor TUserDB.Destroy;
begin
  if Assigned(FDB) then
    sqlite3_close(FDB);
  FLock.Free;
  inherited Destroy;
end;

procedure TUserDB.InitDB;
var
  ErrCode: integer;
  SQL: pansichar;
begin
  // Создаем таблицу пользователей
  SQL := 'CREATE TABLE IF NOT EXISTS users (' +
         'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
         'username TEXT UNIQUE NOT NULL,' +
         'password_hash TEXT NOT NULL,' +
         'salt TEXT NOT NULL' + ')';
  ErrCode := sqlite3_exec(FDB, SQL, nil, nil, nil);
  if ErrCode <> SQLITE_OK then
    raise Exception.Create('Failed to create users table: ' + sqlite3_errmsg(FDB));

  // Создаем индекс для username
  SQL := 'CREATE INDEX IF NOT EXISTS idx_username ON users(username)';
  sqlite3_exec(FDB, SQL, nil, nil, nil);

  // Создаем таблицу заметок в той же БД
  SQL := 'CREATE TABLE IF NOT EXISTS notes (' +
         'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
         'user_id INTEGER NOT NULL,' +
         'title TEXT NOT NULL,' +
         'content TEXT NOT NULL,' +
         'created_at DATETIME DEFAULT CURRENT_TIMESTAMP,' +
         'FOREIGN KEY(user_id) REFERENCES users(id)' + ')';
  ErrCode := sqlite3_exec(FDB, SQL, nil, nil, nil);
  if ErrCode <> SQLITE_OK then
    raise Exception.Create('Failed to create notes table: ' + sqlite3_errmsg(FDB));

  // Создаем индекс для user_id
  SQL := 'CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)';
  sqlite3_exec(FDB, SQL, nil, nil, nil);
end;

function TUserDB.RegisterUser(const Username, Password: string): boolean;
var
  Stmt: Psqlite3_stmt;
  Salt, Hash: string;
  SQL: pansichar;
begin
  Result := False;
  Salt := GenerateSalt;
  Hash := HashPassword(Password, Salt);

  FLock.Enter;
  try
    SQL := 'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_text(Stmt, 1, pansichar(ansistring(Username)), -1, nil);
    sqlite3_bind_text(Stmt, 2, pansichar(ansistring(Hash)), -1, nil);
    sqlite3_bind_text(Stmt, 3, pansichar(ansistring(Salt)), -1, nil);

    if sqlite3_step(Stmt) <> SQLITE_DONE then
    begin
      // Если ошибка - нарушение уникальности (логин занят), возвращаем False
      if sqlite3_errcode(FDB) = SQLITE_CONSTRAINT then
        Exit(False)
      else
        raise Exception.Create('Insert failed: ' + sqlite3_errmsg(FDB));
    end;

    Result := True;
    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

function TUserDB.Authenticate(const Username, Password: string;
  out UserID: integer): boolean;
var
  Stmt: Psqlite3_stmt;
  StoredHash, Salt: string;
  SQL: pansichar;
begin
  Result := False;
  UserID := -1;

  FLock.Enter;
  try
    SQL := 'SELECT id, password_hash, salt FROM users WHERE username = ?';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_text(Stmt, 1, pansichar(ansistring(Username)), -1, nil);

    if sqlite3_step(Stmt) = SQLITE_ROW then
    begin
      UserID := sqlite3_column_int(Stmt, 0);
      StoredHash := string(sqlite3_column_text(Stmt, 1));
      Salt := string(sqlite3_column_text(Stmt, 2));
      Result := HashPassword(Password, Salt) = StoredHash;
    end;

    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

procedure TUserDB.SaveNote(const UserID: integer; const Title, Content: string);
var
  Stmt: Psqlite3_stmt;
  SQL: pansichar;
begin
  FLock.Enter;
  try
    SQL := 'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_int(Stmt, 1, UserID);
    sqlite3_bind_text(Stmt, 2, pansichar(ansistring(Title)), -1, nil);
    sqlite3_bind_text(Stmt, 3, pansichar(ansistring(Content)), -1, nil);

    if sqlite3_step(Stmt) <> SQLITE_DONE then
      raise Exception.Create('Insert failed: ' + sqlite3_errmsg(FDB));

    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

procedure TUserDB.UpdateNote(const UserID, NoteID: integer;
  const Title, Content: string);
var
  Stmt: Psqlite3_stmt;
  SQL: pansichar;
begin
  FLock.Enter;
  try
    SQL := 'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_text(Stmt, 1, pansichar(ansistring(Title)), -1, nil);
    sqlite3_bind_text(Stmt, 2, pansichar(ansistring(Content)), -1, nil);
    sqlite3_bind_int(Stmt, 3, NoteID);
    sqlite3_bind_int(Stmt, 4, UserID);

    if sqlite3_step(Stmt) <> SQLITE_DONE then
      raise Exception.Create('Update failed: ' + sqlite3_errmsg(FDB));

    if sqlite3_changes(FDB) = 0 then
      raise Exception.Create('Note not found or access denied');

    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

procedure TUserDB.DeleteNote(const UserID, NoteID: integer);
var
  Stmt: Psqlite3_stmt;
  SQL: pansichar;
begin
  FLock.Enter;
  try
    SQL := 'DELETE FROM notes WHERE id = ? AND user_id = ?';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_int(Stmt, 1, NoteID);
    sqlite3_bind_int(Stmt, 2, UserID);

    if sqlite3_step(Stmt) <> SQLITE_DONE then
      raise Exception.Create('Delete failed: ' + sqlite3_errmsg(FDB));

    if sqlite3_changes(FDB) = 0 then
      raise Exception.Create('Note not found or access denied');

    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

procedure TUserDB.GetNotes(const UserID: integer; out Notes: TJSONArray);
var
  Stmt: Psqlite3_stmt;
  SQL: pansichar;
  NoteObj: TJSONObject;
begin
  Notes := TJSONArray.Create;
  FLock.Enter;
  try
    SQL := 'SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC';
    if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
      raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

    sqlite3_bind_int(Stmt, 1, UserID);

    while sqlite3_step(Stmt) = SQLITE_ROW do
    begin
      NoteObj := TJSONObject.Create;
      NoteObj.Add('id', sqlite3_column_int(Stmt, 0));
      NoteObj.Add('title', string(sqlite3_column_text(Stmt, 1)));
      NoteObj.Add('content', string(sqlite3_column_text(Stmt, 2)));
      NoteObj.Add('createdAt', string(sqlite3_column_text(Stmt, 3)));
      Notes.Add(NoteObj);
    end;

    sqlite3_finalize(Stmt);
  finally
    FLock.Leave;
  end;
end;

// === Глобальные переменные ===
var
  UserDB: TUserDB;
  SessionStore: TStringList; // session_id -> user_id
  SessionLock: TCriticalSection;

function GetUserIDFromSession(const SessionID: string): integer;
begin
  Result := -1;
  if SessionID = '' then Exit;
  SessionLock.Enter;
  try
    Result := StrToIntDef(SessionStore.Values[SessionID], -1);
  finally
    SessionLock.Leave;
  end;
end;

// === Обработчики API ===
procedure AuthHandler(W: TResponseWriter; R: TRequest);
var
  JSON: TJSONObject;
  Username, Password: string;
  UserID: integer;
  SessionID: string;
begin
  if R.Method = 'POST' then
  begin
    // Login
    JSON := nil;
    try
      JSON := GetJSON(R.Body) as TJSONObject;
      Username := JSON.Get('username', '');
      Password := JSON.Get('password', '');

      if UserDB.Authenticate(Username, Password, UserID) then
      begin
        SessionID := IntToHex(Random(MaxInt), 8) + IntToHex(Random(MaxInt), 8);
        SessionLock.Enter;
        try
          SessionStore.Values[SessionID] := IntToStr(UserID);
        finally
          SessionLock.Leave;
        end;

        W.SetCookie('session_id', SessionID, '/', '', 0, 3600, R.TLS,
          True, ssLax);
        W.Write('{"status":"ok"}');
      end
      else
      begin
        W.WriteHeader(401);
        W.Write('{"error":"Invalid credentials"}');
      end;
    except
      on E: Exception do
      begin
        W.WriteHeader(400);
        W.Write('{"error":"Invalid JSON"}');
      end;
    end;
    if Assigned(JSON) then JSON.Free;
  end
  else if R.Method = 'DELETE' then
  begin
    // Logout
    SessionID := R.CookieValue('session_id');
    if SessionID <> '' then
    begin
      SessionLock.Enter;
      try
        SessionStore.Delete(SessionStore.IndexOfName(SessionID));
      finally
        SessionLock.Leave;
      end;
    end;
    W.SetCookie('session_id', '', '/', '', 0, 0, R.TLS, True, ssLax);
    W.Write('{"status":"ok"}');
  end
  else
  begin
    W.WriteHeader(405);
  end;
end;

procedure RegisterHandler(W: TResponseWriter; R: TRequest);
var
  JSON: TJSONObject;
  Username, Password: string;
begin
  if R.Method <> 'POST' then
  begin
    W.WriteHeader(405);
    Exit;
  end;

  JSON := nil;
  try
    JSON := GetJSON(R.Body) as TJSONObject;
    Username := JSON.Get('username', '');
    Password := JSON.Get('password', '');

    if (Username = '') or (Password = '') then
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Username and password required"}');
      Exit;
    end;

    if UserDB.RegisterUser(Username, Password) then
    begin
      W.WriteHeader(201);
      W.Write('{"status":"created"}');
    end
    else
    begin
      W.WriteHeader(409);
      W.Write('{"error":"Username already exists"}');
    end;
  except
    on E: Exception do
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Invalid JSON"}');
    end;
  end;
  if Assigned(JSON) then JSON.Free;
end;

procedure NotesHandler(W: TResponseWriter; R: TRequest);
var
  SessionID: string;
  UserID: integer;
  JSON: TJSONObject;
  NoteID: integer;
  Arr: TJSONArray;
begin
  SessionID := R.CookieValue('session_id');
  UserID := GetUserIDFromSession(SessionID);
  if UserID = -1 then
  begin
    W.WriteHeader(401);
    W.Write('{"error":"Unauthorized"}');
    Exit;
  end;

  if R.Method = 'GET' then
  begin
    UserDB.GetNotes(UserID, Arr);
    W.Header.SetValue('Content-Type', 'application/json');
    W.Write(Arr.AsJSON);
    Arr.Free;
  end
  else if R.Method = 'POST' then
  begin
    JSON := nil;
    try
      JSON := GetJSON(R.Body) as TJSONObject;
      UserDB.SaveNote(UserID, JSON.Get('title', ''), JSON.Get('content', ''));
      W.WriteHeader(201);
      W.Write('{"status":"created"}');
    except
      on E: Exception do
      begin
        W.WriteHeader(400);
        W.Write('{"error":"Invalid JSON"}');
      end;
    end;
    if Assigned(JSON) then JSON.Free;
  end
  else if R.Method = 'PUT' then
  begin
    NoteID := StrToIntDef(R.QueryValue('id'), -1);
    if NoteID = -1 then
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Missing note id"}');
      Exit;
    end;
    JSON := nil;
    try
      JSON := GetJSON(R.Body) as TJSONObject;
      UserDB.UpdateNote(UserID, NoteID, JSON.Get('title', ''), JSON.Get('content', ''));
      W.Write('{"status":"updated"}');
    except
      on E: Exception do
      begin
        if E.Message = 'Note not found or access denied' then
        begin
           W.WriteHeader(404);
           W.Write('{"error":"Note not found"}');
        end
        else
        begin
           W.WriteHeader(400);
           W.Write('{"error":"Invalid JSON"}');
        end;
      end;
    end;
    if Assigned(JSON) then JSON.Free;
  end
  else if R.Method = 'DELETE' then
  begin
    NoteID := StrToIntDef(R.QueryValue('id'), -1);
    if NoteID = -1 then
    begin
      W.WriteHeader(400);
      W.Write('{"error":"Missing note id"}');
      Exit;
    end;
    try
      UserDB.DeleteNote(UserID, NoteID);
      W.WriteHeader(204); // No Content
    except
      on E: Exception do
      begin
        if E.Message = 'Note not found or access denied' then
        begin
           W.WriteHeader(404);
           W.Write('{"error":"Note not found"}');
        end
        else
        begin
           W.WriteHeader(500);
           W.Write('{"error":"Internal Server Error"}');
        end;
      end;
    end;
  end
  else
  begin
    W.WriteHeader(405);
  end;
end;

// === Статика ===
procedure StaticHandler(W: TResponseWriter; R: TRequest);
var
  FilePath: string;
  Ext: string;
  ContentType: string;
begin
  if R.Path = '/' then
    FilePath := 'frontend/index.html'
  else
    FilePath := 'frontend' + R.Path;

  if not FileExists(FilePath) then
  begin
    W.WriteHeader(404);
    W.Write('Not found');
    Exit;
  end;

  Ext := LowerCase(ExtractFileExt(FilePath));
  case Ext of
    '.html': ContentType := 'text/html';
    '.js': ContentType := 'application/javascript';
    '.css': ContentType := 'text/css';
    '.png', '.jpg', '.jpeg': ContentType := 'image/' + Copy(Ext, 2, MaxInt);
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
begin
  Randomize;
  SSLLibraryInit;

  // Используем единый файл базы данных 'noteflow.db'
  UserDB := TUserDB.Create('noteflow.db');
  SessionStore := TStringList.Create;
  SessionLock := TCriticalSection.Create;

  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);

    Srv.HandleFunc('/api/auth', @AuthHandler);
    Srv.HandleFunc('/api/register', @RegisterHandler);
    Srv.HandleFunc('/api/notes', @NotesHandler);
    Srv.HandleFunc('/', @StaticHandler);
    Srv.HandleFunc('/style.css', @StaticHandler);

    WriteLn('NoteFlow Server started on http://localhost:3000');
    WriteLn('Database stored in: noteflow.db');
    Srv.ListenAndServe(':3000');
  finally
    SessionStore.Free;
    SessionLock.Free;
    UserDB.Free;
    Srv.Free;
  end;
end.
