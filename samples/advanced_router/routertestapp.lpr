program routertestapp;


{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  SysUtils, Classes, fpjson, jsonparser,
  AdvancedHTTPServer, AdvancedHTTPRouter;

type
  TStringObject = class
    Str: string;
    constructor Create(const AStr: string);
  end;

  constructor TStringObject.Create(const AStr: string);
  begin
    inherited Create;
    Str := AStr;
  end;
type
  TAppState = class
  private
    FUsers: TStringList; // id -> JSON string in Objects[]
    FNextID: integer;
    function FindIndexByID(ID: integer): integer;
  public
    constructor Create;
    destructor Destroy; override;
    function AddUser(const Name, Email: string): integer;
    function GetUser(ID: integer): TJSONObject;
    function UpdateUser(ID: integer; const Name, Email: string): boolean;
    function DeleteUser(ID: integer): boolean;
    function ListUsers: TJSONArray;
  end;

constructor TAppState.Create;
begin
  inherited Create;
  FUsers := TStringList.Create;
  FUsers.CaseSensitive := False;
  FUsers.Sorted := False;
  FUsers.Duplicates := dupError;
  FNextID := 1;
end;

destructor TAppState.Destroy;
var
  I: Integer;
begin
  for I := 0 to FUsers.Count - 1 do
    FUsers.Objects[I].Free;
  FUsers.Free;
  inherited Destroy;
end;

function TAppState.FindIndexByID(ID: integer): integer;
begin
  Result := FUsers.IndexOf(IntToStr(ID));
end;

function TAppState.AddUser(const Name, Email: string): integer;
var
  Obj: TJSONObject;
begin
  Result := FNextID;
  Inc(FNextID);

  Obj := TJSONObject.Create;
  Obj.Integers['id'] := Result;
  Obj.Strings['name'] := Name;
  Obj.Strings['email'] := Email;

  FUsers.AddObject(IntToStr(Result), TStringObject.Create(Obj.AsJSON));
  Obj.Free;
end;

function TAppState.GetUser(ID: integer): TJSONObject;
var
  Idx: integer;
  S: string;
begin
  Result := nil;
  Idx := FindIndexByID(ID);
  if Idx < 0 then Exit;

  S := TStringObject(FUsers.Objects[Idx]).Str;
  Result := GetJSON(S) as TJSONObject;
end;

function TAppState.UpdateUser(ID: integer; const Name, Email: string): boolean;
var
  Idx: integer;
  Obj: TJSONObject;
begin
  Result := False;
  Idx := FindIndexByID(ID);
  if Idx < 0 then Exit;

  Obj := GetJSON(TStringObject(FUsers.Objects[Idx]).Str) as TJSONObject;
  try
    Obj.Strings['name'] := Name;
    Obj.Strings['email'] := Email;
    TStringObject(FUsers.Objects[Idx]).Str := Obj.AsJSON;
    Result := True;
  finally
    Obj.Free;
  end;
end;

function TAppState.DeleteUser(ID: integer): boolean;
var
  Idx: integer;
begin
  Idx := FindIndexByID(ID);
  Result := Idx >= 0;
  if not Result then Exit;

  FUsers.Objects[Idx].Free;
  FUsers.Delete(Idx);
end;

function TAppState.ListUsers: TJSONArray;
var
  I: integer;
begin
  Result := TJSONArray.Create;
  for I := 0 to FUsers.Count - 1 do
    Result.Add(GetJSON(TStringObject(FUsers.Objects[I]).Str) as TJSONObject);
end;

{ Middleware }

procedure AuthMiddleware(C: TObject);
begin
  // simple sample: check of X-API-Key header
  if THTTPRouterContext(C).Header('X-API-Key') <> 'secret123' then
  begin
    THTTPRouterContext(C).Text(401, 'Unauthorized');
    THTTPRouterContext(C).Abort;
  end
  else
    THTTPRouterContext(C).Next;
end;

procedure StaticHandler(C: TObject);
var
  Ctx: THTTPRouterContext;
  FilePath, Ext, ContentType: string;
begin
  Ctx := THTTPRouterContext(C);

  if (Ctx.R.Method <> 'GET') and (Ctx.R.Method <> 'HEAD') then
  begin
    Ctx.Status(405);
    Exit;
  end;

  if Ctx.R.Path = '/' then
    FilePath := 'frontend/index.html'
  else
    FilePath := 'frontend' + Ctx.R.Path;

  if not FileExists(FilePath) then
  begin
    Ctx.Text(404, 'Not found');
    Exit;
  end;

  Ext := LowerCase(ExtractFileExt(FilePath));
  case Ext of
    '.html': ContentType := 'text/html; charset=utf-8';
    '.js': ContentType := 'application/javascript';
    '.css': ContentType := 'text/css';
    '.png': ContentType := 'image/png';
    '.jpg', '.jpeg': ContentType := 'image/jpeg';
    '.gif': ContentType := 'image/gif';
    '.svg': ContentType := 'image/svg+xml';
    else
      ContentType := 'application/octet-stream';
  end;

  Ctx.W.Header.SetValue('Content-Type', ContentType);
  ServeFile(Ctx.W, Ctx.R, FilePath);
end;

{ Main }

var
  AppState : TAppState;
  Server: THTTPServer;
  Router: THTTPRouter;
  APIGroup: THTTPRouterGroup;
begin
  AppState := TAppState.Create;
  try
    Server := THTTPServer.Create;
    try
      Server.MaxHeaderBytes := 65536;
      Server.MaxBodyBytes := 10 * 1024 * 1024; // 10MB

      Router := THTTPRouter.Create(Server);
      try
        // global middleware (logging)
        Router.Use(
          procedure(C: TObject)
          begin
            WriteLn('[LOG] ', THTTPRouterContext(C).R.Method, ' ', THTTPRouterContext(C).R.URL);
            THTTPRouterContext(C).Next;
          end
        );

        // Main page - get SPA
        Router.GET('/', [@StaticHandler]);

        // API group
        APIGroup := Router.Group('/api') as THTTPRouterGroup;
        APIGroup.Use(@AuthMiddleware); // защищаем весь API

        // POST /api/users
        APIGroup.POST('/users',
          [
            procedure(C: TObject)
            var
              Body: string;
              JSON: TJSONObject;
              Name, Email: string;
              ID: integer;
            begin
              Body := THTTPRouterContext(C).R.Body;
              if Body = '' then
              begin
                THTTPRouterContext(C).Text(400, 'Empty body');
                Exit;
              end;
              JSON := GetJSON(Body) as TJSONObject;
              try
                Name := JSON.Get('name', '');
                Email := JSON.Get('email', '');
                if (Name = '') or (Email = '') then
                begin
                  THTTPRouterContext(C).Text(400, 'Name and email required');
                  Exit;
                end;
                ID := AppState.AddUser(Name, Email);
                JSON.Integers['id'] := ID;
                THTTPRouterContext(C).JSON(201, JSON);
              finally
                JSON.Free;
              end;
            end
          ]
        );

        // GET /api/users/:id
        APIGroup.GET('/users/:id',
          [
            procedure(C: TObject)
            var
              ID: integer;
              User: TJSONObject;
            begin
              ID := StrToIntDef(THTTPRouterContext(C).Param('id'), -1);
              if ID <= 0 then
              begin
                THTTPRouterContext(C).Text(400, 'Invalid ID');
                Exit;
              end;
              User := AppState.GetUser(ID);
              if not Assigned(User) then
                THTTPRouterContext(C).Text(404, 'User not found')
              else
              begin
                THTTPRouterContext(C).JSON(200, User);
                User.Free;
              end;
            end
          ]
        );

        // PUT /api/users/:id
        APIGroup.PUT('/users/:id',
          [
            procedure(C: TObject)
            var
              ID: integer;
              Body: string;
              JSON: TJSONObject;
              Name, Email: string;
            begin
              ID := StrToIntDef(THTTPRouterContext(C).Param('id'), -1);
              if ID <= 0 then
              begin
                THTTPRouterContext(C).Text(400, 'Invalid ID');
                Exit;
              end;
              if not Assigned(AppState.GetUser(ID)) then
              begin
                THTTPRouterContext(C).Text(404, 'User not found');
                Exit;
              end;
              Body := THTTPRouterContext(C).R.Body;
              JSON := GetJSON(Body) as TJSONObject;
              try
                Name := JSON.Get('name', '');
                Email := JSON.Get('email', '');
                AppState.UpdateUser(ID, Name, Email);
                THTTPRouterContext(C).Text(204, '');
              finally
                JSON.Free;
              end;
            end
          ]
        );

        // DELETE /api/users/:id
        APIGroup.DELETE('/users/:id',
          [
            procedure(C: TObject)
            var
              ID: integer;
            begin
              ID := StrToIntDef(THTTPRouterContext(C).Param('id'), -1);
              if ID <= 0 then
              begin
                THTTPRouterContext(C).Text(400, 'Invalid ID');
                Exit;
              end;
              AppState.DeleteUser(ID);
              THTTPRouterContext(C).Text(204, '');
            end
          ]
        );

        // GET /api/users
        APIGroup.GET('/users',
          [
            procedure(C: TObject)
            begin
              THTTPRouterContext(C).JSON(200, AppState.ListUsers);
            end
          ]
        );

        // Static
        Router.Any('/public/*filepath',
          [
            procedure(C: TObject)
            var
              Path: string;
              FullPath: string;
            begin
              Path := THTTPRouterContext(C).Param('filepath');
              FullPath := 'public/' + StringReplace(Path, '..', '', [rfReplaceAll]);
              if FileExists(FullPath) then
                ServeFile(THTTPRouterContext(C).W, THTTPRouterContext(C).R, FullPath)
              else
                THTTPRouterContext(C).Text(404, 'Not Found');
            end
          ]
        );

        Router.Mount;
        WriteLn('Starting server on http://localhost:8080');
        Server.ListenAndServe(':8080');
      finally
        Router.Free;
      end;
    finally
      Server.Free;
    end;
  finally
    AppState.Free;
  end;
end.
