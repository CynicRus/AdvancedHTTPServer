unit NoteStorage;

{$MODE OBJFPC}{$H+}
interface

uses Classes, SysUtils, DateUtils;

type
  TNote = record
    ID: string;
    EncryptedData: string; // Зашифрованный JSON от клиента
    CreatedAt: TDateTime;
    ExpiresAt: TDateTime;  // время самоуничтожения
    MaxViews: Integer;     // обычно 1
    Views: Integer;
  end;

  INoteStorage = class
  public
    // Создать новую заметку → вернуть ID
    function CreateNote(const AEncryptedData: string; AMaxViews: Integer = 1; AExpireInSec: Integer = 3600): string; virtual; abstract;
    // Получить заметку по ID (и увеличить счётчик просмотров)
    function GetNote(const AID: string; out ANote: TNote): Boolean; virtual; abstract;
    // Удалить заметку (после просмотра или по таймауту)
    procedure DeleteNote(const AID: string); virtual; abstract;
    // Удалить все просроченные заметки (фоновая задача)
    procedure CleanupExpired; virtual; abstract;
  end;

  TSQLiteNoteStorage = class(INoteStorage)
  private
    FDB: Pointer; // Psqlite3
  public
    constructor Create(const FileName: string);
    destructor Destroy; override;
    function CreateNote(const AEncryptedData: string; AMaxViews: Integer = 1; AExpireInSec: Integer = 3600): string; override;
    function GetNote(const AID: string; out ANote: TNote): Boolean; override;
    procedure DeleteNote(const AID: string); override;
    procedure CleanupExpired; override;
  end;

implementation

uses sqlite3dyn, sqlite3conn;

{ TSQLiteNoteStorage }

constructor TSQLiteNoteStorage.Create(const FileName: string);
var
  DB: Psqlite3;
begin
  InitialiseSQLite;
  if sqlite3_open(PAnsiChar(AnsiString(FileName)), @DB) <> SQLITE_OK then
    raise Exception.Create('Cannot open database');
  FDB := DB;

  // Создаём таблицу с полем expires_at
  sqlite3_exec(DB,
    'CREATE TABLE IF NOT EXISTS notes (' +
    'id TEXT PRIMARY KEY,' +
    'encrypted_data TEXT NOT NULL,' +
    'created_at DATETIME DEFAULT CURRENT_TIMESTAMP,' +
    'expires_at DATETIME NOT NULL,' +
    'max_views INTEGER NOT NULL,' +
    'views INTEGER NOT NULL DEFAULT 0' +
    ')', nil, nil, nil);

  // Индекс для быстрой очистки
  sqlite3_exec(DB, 'CREATE INDEX IF NOT EXISTS idx_expires ON notes(expires_at)', nil, nil, nil);
end;

destructor TSQLiteNoteStorage.Destroy;
begin
  if Assigned(FDB) then
    sqlite3_close(Psqlite3(FDB));
  inherited Destroy;
end;

function TSQLiteNoteStorage.CreateNote(const AEncryptedData: string; AMaxViews: Integer; AExpireInSec: Integer): string;
var
  Stmt: Psqlite3_stmt;
  ID: string;
  I: Integer;
  NowStr, ExpireStr: string;
begin
  // Генерируем ID
  Randomize;
  ID := '';
  for I := 1 to 32 do
    ID := ID + 'abcdefghijklmnopqrstuvwxyz0123456789'[Random(36) + 1];
  Result := ID;

  // Форматируем даты как ISO8601 (SQLite понимает)
  NowStr := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now);
  ExpireStr := FormatDateTime('yyyy-mm-dd hh:nn:ss', IncSecond(Now, AExpireInSec));

  if sqlite3_prepare_v2(Psqlite3(FDB),
    'INSERT INTO notes (id, encrypted_data, expires_at, max_views) VALUES (?, ?, ?, ?)',
    -1, @Stmt, nil) <> SQLITE_OK then
    raise Exception.Create('Prepare failed');

  sqlite3_bind_text(Stmt, 1, PAnsiChar(AnsiString(ID)), -1, nil);
  sqlite3_bind_text(Stmt, 2, PAnsiChar(AnsiString(AEncryptedData)), -1, nil);
  sqlite3_bind_text(Stmt, 3, PAnsiChar(AnsiString(ExpireStr)), -1, nil);
  sqlite3_bind_int(Stmt, 4, AMaxViews);

  if sqlite3_step(Stmt) <> SQLITE_DONE then
    raise Exception.Create('Insert failed');

  sqlite3_finalize(Stmt);
end;

function TSQLiteNoteStorage.GetNote(const AID: string; out ANote: TNote): Boolean;
var
  Stmt: Psqlite3_stmt;
begin
  Result := False;
  FillChar(ANote, SizeOf(ANote), 0);

  if sqlite3_prepare_v2(Psqlite3(FDB),
    'SELECT encrypted_data, created_at, expires_at, max_views, views FROM notes WHERE id = ?',
    -1, @Stmt, nil) <> SQLITE_OK then Exit;

  sqlite3_bind_text(Stmt, 1, PAnsiChar(AnsiString(AID)), -1, nil);

  if sqlite3_step(Stmt) = SQLITE_ROW then
  begin
    ANote.ID := AID;
    ANote.EncryptedData := string(sqlite3_column_text(Stmt, 0));
    ANote.CreatedAt := Now; // упрощённо
    ANote.ExpiresAt := ScanDateTime('yyyy-mm-dd hh:nn:ss', string(sqlite3_column_text(Stmt, 2)));
    ANote.MaxViews := sqlite3_column_int(Stmt, 3);
    ANote.Views := sqlite3_column_int(Stmt, 4);
    Result := True;
  end;

  sqlite3_finalize(Stmt);

  if Result then
  begin
    // Увеличиваем счётчик просмотров
    if sqlite3_prepare_v2(Psqlite3(FDB),
      'UPDATE notes SET views = views + 1 WHERE id = ?', -1, @Stmt, nil) = SQLITE_OK then
    begin
      sqlite3_bind_text(Stmt, 1, PAnsiChar(AnsiString(AID)), -1, nil);
      sqlite3_step(Stmt);
      sqlite3_finalize(Stmt);
    end;
  end;
end;

procedure TSQLiteNoteStorage.DeleteNote(const AID: string);
var
  Stmt: Psqlite3_stmt;
begin
  if sqlite3_prepare_v2(Psqlite3(FDB),
    'DELETE FROM notes WHERE id = ?', -1, @Stmt, nil) = SQLITE_OK then
  begin
    sqlite3_bind_text(Stmt, 1, PAnsiChar(AnsiString(AID)), -1, nil);
    sqlite3_step(Stmt);
    sqlite3_finalize(Stmt);
  end;
end;

procedure TSQLiteNoteStorage.CleanupExpired;
var
  Stmt: Psqlite3_stmt;
  NowStr: string;
begin
  NowStr := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now);
  if sqlite3_prepare_v2(Psqlite3(FDB),
    'DELETE FROM notes WHERE expires_at <= ? OR views >= max_views',
    -1, @Stmt, nil) = SQLITE_OK then
  begin
    sqlite3_bind_text(Stmt, 1, PAnsiChar(AnsiString(NowStr)), -1, nil);
    sqlite3_step(Stmt);
    sqlite3_finalize(Stmt);
  end;
end;

end.
