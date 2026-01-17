program TaskFlowServer;

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
  dateutils,
  AdvancedHTTPServer;

type
  TTaskDB = class
  private
    FDB: Psqlite3;
    FLock: TCriticalSection;
    procedure InitDB;
  public
    constructor Create(const FileName: string);
    destructor Destroy; override;
    procedure SaveTask(const ClientIP, Title: string);
    procedure UpdateTask(const ClientIP: string; ID: integer;
      const Title: string; Completed: boolean);
    procedure DeleteTask(const ClientIP: string; ID: integer);
    procedure GetTasks(const ClientIP: string; out Tasks: TJSONArray);
  end;

  // === Реализация через C API ===

  constructor TTaskDB.Create(const FileName: string);
  begin
    inherited Create;
    FLock := TCriticalSection.Create;
    InitialiseSQLite;
    if sqlite3_open(pansichar(ansistring(FileName)), @FDB) <> SQLITE_OK then
      raise Exception.Create('Cannot open database: ' + sqlite3_errmsg(@FDB));
    InitDB;
  end;

  destructor TTaskDB.Destroy;
  begin
    if Assigned(FDB) then
      sqlite3_close(@FDB);
    FLock.Free;
    inherited Destroy;
  end;

  procedure TTaskDB.InitDB;
  var
    ErrCode: integer;
    SQL: pansichar;
  begin
    SQL := 'CREATE TABLE IF NOT EXISTS tasks (' +
      'id INTEGER PRIMARY KEY AUTOINCREMENT,' + 'client_ip TEXT NOT NULL,' +
      'title TEXT NOT NULL,' + 'completed INTEGER NOT NULL DEFAULT 0,' +
      'created_at DATETIME DEFAULT CURRENT_TIMESTAMP' + ')';
    ErrCode := sqlite3_exec(FDB, SQL, nil, nil, nil);
    if ErrCode <> SQLITE_OK then
      raise Exception.Create('Failed to create table');

    SQL := 'CREATE INDEX IF NOT EXISTS idx_client_ip ON tasks(client_ip)';
    ErrCode := sqlite3_exec(FDB, SQL, nil, nil, nil);
    if ErrCode <> SQLITE_OK then
      raise Exception.Create('Failed to create index');
  end;

  procedure TTaskDB.SaveTask(const ClientIP, Title: string);
  var
    Stmt: Psqlite3_stmt;
    SQL: pansichar;
  begin
    FLock.Enter;
    try
      SQL := 'INSERT INTO tasks (client_ip, title, completed) VALUES (?, ?, 0)';
      if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
        raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(@FDB));

      sqlite3_bind_text(Stmt, 1, pansichar(ansistring(ClientIP)), -1, nil);
      sqlite3_bind_text(Stmt, 2, pansichar(ansistring(Title)), -1, nil);

      if sqlite3_step(Stmt) <> SQLITE_DONE then
        raise Exception.Create('Insert failed: ' + sqlite3_errmsg(@FDB));

      sqlite3_finalize(Stmt);
    finally
      FLock.Leave;
    end;
  end;

  procedure TTaskDB.UpdateTask(const ClientIP: string; ID: integer;
  const Title: string; Completed: boolean);
  var
    Stmt: Psqlite3_stmt;
    SQL: pansichar;
  begin
    FLock.Enter;
    try
      if Title <> '' then
        SQL := 'UPDATE tasks SET title = ?, completed = ? WHERE id = ? AND client_ip = ?'
      else
        SQL := 'UPDATE tasks SET completed = ? WHERE id = ? AND client_ip = ?';

      if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
        raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

      if Title <> '' then
      begin
        sqlite3_bind_text(Stmt, 1, pansichar(ansistring(Title)), -1, nil);
        sqlite3_bind_int(Stmt, 2, Ord(Completed));
        sqlite3_bind_int(Stmt, 3, ID);
        sqlite3_bind_text(Stmt, 4, pansichar(ansistring(ClientIP)), -1, nil);
      end
      else
      begin
        sqlite3_bind_int(Stmt, 1, Ord(Completed));
        sqlite3_bind_int(Stmt, 2, ID);
        sqlite3_bind_text(Stmt, 3, pansichar(ansistring(ClientIP)), -1, nil);
      end;

      if sqlite3_step(Stmt) <> SQLITE_DONE then
        raise Exception.Create('Update failed: ' + sqlite3_errmsg(FDB));

      if sqlite3_changes(FDB) = 0 then
        raise Exception.Create('Task not found or access denied');

      sqlite3_finalize(Stmt);
    finally
      FLock.Leave;
    end;
  end;

  procedure TTaskDB.DeleteTask(const ClientIP: string; ID: integer);
  var
    Stmt: Psqlite3_stmt;
    SQL: pansichar;
  begin
    FLock.Enter;
    try
      SQL := 'DELETE FROM tasks WHERE id = ? AND client_ip = ?';
      if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
        raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

      sqlite3_bind_int(Stmt, 1, ID);
      sqlite3_bind_text(Stmt, 2, pansichar(ansistring(ClientIP)), -1, nil);

      if sqlite3_step(Stmt) <> SQLITE_DONE then
        raise Exception.Create('Delete failed: ' + sqlite3_errmsg(FDB));

      if sqlite3_changes(FDB) = 0 then
        raise Exception.Create('Task not found or access denied');

      sqlite3_finalize(Stmt);
    finally
      FLock.Leave;
    end;
  end;

  procedure TTaskDB.GetTasks(const ClientIP: string; out Tasks: TJSONArray);
  var
    Stmt: Psqlite3_stmt;
    SQL: pansichar;
    TaskObj: TJSONObject;
  begin
    Tasks := TJSONArray.Create;
    FLock.Enter;
    try
      SQL :=
        'SELECT id, title, completed, created_at FROM tasks WHERE client_ip = ? ORDER BY created_at DESC';
      if sqlite3_prepare_v2(FDB, SQL, -1, @Stmt, nil) <> SQLITE_OK then
        raise Exception.Create('Prepare failed: ' + sqlite3_errmsg(FDB));

      sqlite3_bind_text(Stmt, 1, pansichar(ansistring(ClientIP)), -1, nil);

      while sqlite3_step(Stmt) = SQLITE_ROW do
      begin
        TaskObj := TJSONObject.Create;
        TaskObj.Add('id', sqlite3_column_int(Stmt, 0));
        TaskObj.Add('title', string(sqlite3_column_text(Stmt, 1)));
        TaskObj.Add('completed', sqlite3_column_int(Stmt, 2) = 1);
        TaskObj.Add('createdAt', string(sqlite3_column_text(Stmt, 3)));
        Tasks.Add(TaskObj);
      end;

      sqlite3_finalize(Stmt);
    finally
      FLock.Leave;
    end;
  end;

  // === Глобальная переменная ===
var
  TaskDB: TTaskDB;

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



  // === ЕДИНЫЙ ХЭНДЛЕР ДЛЯ /api/tasks ===
  procedure TasksHandler(W: TResponseWriter; R: TRequest);
  var
    TaskID: integer;
    JSON: TJSONObject;
    Title: string;
    Completed: boolean;
    Arr: TJSONArray;
  begin
    // Унифицируем метод
    if R.Method = 'GET' then
    begin
      TaskDB.GetTasks(R.RemoteAddr, Arr);
      W.Header.SetValue('Content-Type', 'application/json');
      W.Write(Arr.AsJSON);
      Arr.Free;
    end
    else if R.Method = 'POST' then
    begin
      try
        JSON := GetJSON(R.Body) as TJSONObject;
        Title := Trim(JSON.Get('title', ''));
        if Title = '' then
        begin
          W.WriteHeader(400);
          W.Write('{"error":"Title is required"}');
          Exit;
        end;
        TaskDB.SaveTask(R.RemoteAddr, Title);
        W.WriteHeader(201);
        W.Write('{"status":"created"}');
      except
        on E: Exception do
        begin
          W.WriteHeader(400);
          W.Write('{"error":"Invalid JSON"}');
        end;
      end;
    end
    else if R.Method = 'PUT' then
    begin
      TaskID := StrToIntDef(R.QueryValue('id'), -1);
      if TaskID = -1 then
      begin
        W.WriteHeader(400);
        W.Write('{"error":"Missing id"}');
        Exit;
      end;
      try
        JSON := GetJSON(R.Body) as TJSONObject;
        Completed := JSON.Get('completed', False);
        Title := JSON.Get('title', '');
        TaskDB.UpdateTask(R.RemoteAddr, TaskID, Title, Completed);
        W.Write('{"status":"updated"}');
      except
        on E: Exception do
        begin
          W.WriteHeader(400);
          W.Write('{"error":"Invalid JSON or task not found"}');
        end;
      end;
    end
    else if R.Method = 'DELETE' then
    begin
      TaskID := StrToIntDef(R.QueryValue('id'), -1);
      if TaskID = -1 then
      begin
        W.WriteHeader(400);
        W.Write('{"error":"Missing id"}');
        Exit;
      end;
      try
        TaskDB.DeleteTask(R.RemoteAddr, TaskID);
        W.WriteHeader(204); // No Content
      except
        on E: Exception do
        begin
          W.WriteHeader(404);
          W.Write('{"error":"Task not found"}');
        end;
      end;
    end
    else
    begin
      W.WriteHeader(405);
      W.Header.SetValue('Allow', 'GET, POST, PUT, DELETE');
      W.Write('{"error":"Method not allowed"}');
    end;
  end;

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

  // === Main ===
var
  Srv: THTTPServer;
begin
  TaskDB := TTaskDB.Create('tasks.db');

  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);

    Srv.HandleFunc('/api/tasks', @TasksHandler);

    // Статика
    Srv.HandleFunc('/', @StaticHandler);

    WriteLn('TaskFlow Server started on http://localhost:3000');
    WriteLn('Tasks are stored per IP in tasks.db');
    Srv.ListenAndServe(':3000');
  finally
    Srv.Free;
    TaskDB.Free;
  end;
end.
