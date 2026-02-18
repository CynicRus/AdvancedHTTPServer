unit AdvancedSessionManager;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
{$modeswitch anonymousfunctions}
{$modeswitch functionreferences}

interface

uses
  SysUtils, DateUtils, SyncObjs, HashMap,
  AdvancedHTTPServer;

type
  TSessionSameSite = TResponseWriter.TCookieSameSite;

  // chain sources for reading session id
  TSessionIDSource = (sidCookie, sidHeader, sidQuery);

  // Accessors for absolute expiration stored inside TData
  generic TAbsExpGet<TData> = reference to function(const Data: TData;
    out AbsExpUTC: TDateTime): boolean;
  generic TAbsExpSet<TData> = reference to procedure(var Data: TData;
    const AbsExpUTC: TDateTime);

  TSessionConfig = record
    CookieName: string;          // default: 'session_id'
    HeaderName: string;          // default: '' (disabled). Example: 'X-Session-Id'
    QueryParamName: string;      // default: '' (disabled). Example: 'sid'

    CookiePath: string;          // default: '/'
    CookieDomain: string;        // default: ''
    CookieSecure: boolean;       // default: False
    CookieHTTPOnly: boolean;     // default: True
    CookieSameSite: TSessionSameSite; // default: ssLax
    CookieSessionOnly: boolean;  // default: False (sets Max-Age/Expires)

    IdleTimeoutSec: integer;     // default: 3600
    AbsoluteTimeoutSec: integer; // default: 0 (disabled)
    CleanupIntervalSec: integer; // default: 30
    IDLength: integer;           // default: 64 (hex chars recommended)

    // Order/combination of sources to read ID from (cookie/header/query etc).
    // If empty => default chain: cookie, header(if enabled), query(if enabled)
    IDSources: array of TSessionIDSource;
  end;

  generic TSession<TData> = class
  private
    FID: string;
    FData: TData;
    FFresh: boolean;
    FDestroyed: boolean;
    FExpiresAt: TDateTime; // idle expiration (sliding)
  public
    property ID: string read FID;
    property Fresh: boolean read FFresh;
    property Destroyed: boolean read FDestroyed;
    property ExpiresAtUTC: TDateTime read FExpiresAt;

    // Data is a copy in object; Save() writes it to store
    property Data: TData read FData write FData;
  end;

  { TSessionManager }

  generic TSessionManager<TData> = class
  public
  type
    TSessionObj = specialize TSession<TData>;
    TGetSessionFunc = reference to function(W: TResponseWriter;
      R: TRequest): TSessionObj;
  private
  type
    TSessionRec = record
      Data: TData;
      ExpiresAt: TDateTime; // idle expiration (UTC)
    end;

    TStore = specialize TStringHashMap<TSessionRec>;

    TCleanupContext = record
      Mgr: TSessionManager;
      NowDT: TDateTime;
      ExpiredKeys: array of string;
    end;
  private
    FCfg: TSessionConfig;
    FLock: TCriticalSection;
    FStore: TStore;
    FLastCleanup: TDateTime;

    // abs-expiration accessors (optional)
    FAbsGet: specialize TAbsExpGet<TData>;
    FAbsSet: specialize TAbsExpSet<TData>;

    function NowUTC: TDateTime; inline;
    function MakeAbsTimeoutDT(const NowDT: TDateTime): TDateTime; inline;
    function MakeIdleTimeoutDT(const NowDT: TDateTime): TDateTime; inline;

    function GetAbsExpFromData(const Data: TData; out AbsExpUTC: TDateTime): boolean;
      inline;
    procedure SetAbsExpToData(var Data: TData; const AbsExpUTC: TDateTime); inline;

    procedure EnsureDefaultIDSources;
    function ReadSessionID(R: TRequest): string;
    procedure WriteSessionID(W: TResponseWriter; const ID: string;
      MaxAgeSec: integer; Expire: boolean);
    function NewID: string;

    function IsExpired(const Rec: TSessionRec; const NowDT: TDateTime): boolean; inline;
    procedure MaybeCleanup(const NowDT: TDateTime);
    procedure Cleanup(const NowDT: TDateTime);

    function TryGetRec(const ID: string; out Rec: TSessionRec): boolean; inline;
    procedure PutRec(const ID: string; const Rec: TSessionRec); inline;
    function RemoveRec(const ID: string; out Rec: TSessionRec): boolean; inline;
    class function CleanupIterator(const Key: string; const Value: TSessionRec; Context: Pointer): Boolean; static;
  public
    constructor Create(const ACfg: TSessionConfig);
    destructor Destroy; override;

    // Configure how abs-expiration is stored inside TData
    procedure SetAbsExpirationAccessors(const AGet: specialize TAbsExpGet<TData>;
      const ASet: specialize TAbsExpSet<TData>);

    function Get(W: TResponseWriter; R: TRequest): TSessionObj;
    procedure Save(W: TResponseWriter; const Sess: TSessionObj);
    procedure DestroySession(W: TResponseWriter; const Sess: TSessionObj);

    procedure Regenerate(W: TResponseWriter; const Sess: TSessionObj;
      PreserveData: boolean = True);
    procedure Reset(W: TResponseWriter; const Sess: TSessionObj);

    // Middleware: wraps handler and autosaves before finish.
    function Middleware(const Next: THandlerFunc;
      out GetSession: TGetSessionFunc): THandlerFunc;
  end;

function SessionConfigDefault: TSessionConfig;

implementation

function SessionConfigDefault: TSessionConfig;
begin
  Result.CookieName := 'session_id';
  Result.HeaderName := '';
  Result.QueryParamName := '';

  Result.CookiePath := '/';
  Result.CookieDomain := '';
  Result.CookieSecure := False;
  Result.CookieHTTPOnly := True;
  Result.CookieSameSite := TResponseWriter.TCookieSameSite.ssLax;
  Result.CookieSessionOnly := False;

  Result.IdleTimeoutSec := 3600;
  Result.AbsoluteTimeoutSec := 0;
  Result.CleanupIntervalSec := 30;
  Result.IDLength := 64; // hex chars; 64 => 256-bit id

  SetLength(Result.IDSources, 0);
end;

{ generic TSessionManager<TData> }

constructor TSessionManager.Create(const ACfg: TSessionConfig);
begin
  inherited Create;
  FCfg := ACfg;

  if FCfg.CookieName = '' then FCfg.CookieName := 'session_id';
  if FCfg.CookiePath = '' then FCfg.CookiePath := '/';
  if FCfg.IdleTimeoutSec <= 0 then FCfg.IdleTimeoutSec := 3600;
  if FCfg.CleanupIntervalSec <= 0 then FCfg.CleanupIntervalSec := 30;
  if FCfg.IDLength <= 0 then FCfg.IDLength := 64;

  FLock := TCriticalSection.Create;
  FStore := TStore.Create; // TStringHashMap handles Hash/Compare internally
  // FStore.Sorted := True; // Not applicable to HashMap

  FLastCleanup := 0;
  FAbsGet := nil;
  FAbsSet := nil;

  EnsureDefaultIDSources;
  Randomize;
end;

destructor TSessionManager.Destroy;
begin
  FStore.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TSessionManager.EnsureDefaultIDSources;
var
  L: integer;
begin
  if Length(FCfg.IDSources) <> 0 then Exit;

  L := 0;

  if FCfg.CookieName <> '' then
  begin
    SetLength(FCfg.IDSources, L + 1);
    FCfg.IDSources[L] := sidCookie;
    Inc(L);
  end;

  if FCfg.HeaderName <> '' then
  begin
    SetLength(FCfg.IDSources, L + 1);
    FCfg.IDSources[L] := sidHeader;
    Inc(L);
  end;

  if FCfg.QueryParamName <> '' then
  begin
    SetLength(FCfg.IDSources, L + 1);
    FCfg.IDSources[L] := sidQuery;
    Inc(L);
  end;
end;

procedure TSessionManager.SetAbsExpirationAccessors(
  const AGet: specialize TAbsExpGet<TData>; const ASet: specialize TAbsExpSet<TData>);
begin
  FAbsGet := AGet;
  FAbsSet := ASet;
end;

function TSessionManager.NowUTC: TDateTime; inline;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

function TSessionManager.MakeAbsTimeoutDT(const NowDT: TDateTime): TDateTime; inline;
begin
  if FCfg.AbsoluteTimeoutSec > 0 then
    Result := IncSecond(NowDT, FCfg.AbsoluteTimeoutSec)
  else
    Result := 0;
end;

function TSessionManager.MakeIdleTimeoutDT(const NowDT: TDateTime): TDateTime; inline;
begin
  Result := IncSecond(NowDT, FCfg.IdleTimeoutSec);
end;

function TSessionManager.GetAbsExpFromData(const Data: TData;
  out AbsExpUTC: TDateTime): boolean; inline;
begin
  AbsExpUTC := 0;
  if Assigned(FAbsGet) then
    Exit(FAbsGet(Data, AbsExpUTC));
  Result := False;
end;

procedure TSessionManager.SetAbsExpToData(var Data: TData;
  const AbsExpUTC: TDateTime); inline;
begin
  if Assigned(FAbsSet) then
    FAbsSet(Data, AbsExpUTC);
end;

function TSessionManager.IsExpired(const Rec: TSessionRec;
  const NowDT: TDateTime): boolean; inline;
var
  AbsExp: TDateTime;
begin
  if GetAbsExpFromData(Rec.Data, AbsExp) then
    if (AbsExp > 0) and (NowDT > AbsExp) then Exit(True);

  Result := (Rec.ExpiresAt > 0) and (NowDT > Rec.ExpiresAt);
end;

function TSessionManager.NewID: string;
const
  Hex: array[0..15] of char =
    ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
var
  i: integer;
begin
  SetLength(Result, FCfg.IDLength);
  for i := 1 to Length(Result) do
    Result[i] := Hex[Random(16)];
end;

function TSessionManager.ReadSessionID(R: TRequest): string;
var
  V: string;
  i: integer;
begin
  Result := '';
  if R = nil then Exit('');

  EnsureDefaultIDSources;

  for i := 0 to High(FCfg.IDSources) do
  begin
    case FCfg.IDSources[i] of
      sidCookie:
      begin
        if FCfg.CookieName = '' then Continue;
        V := R.CookieValue(FCfg.CookieName);
        if V <> '' then Exit(V);
      end;
      sidHeader:
      begin
        if FCfg.HeaderName = '' then Continue;
        V := R.Header.GetValue(FCfg.HeaderName);
        if V <> '' then Exit(V);
      end;
      sidQuery:
      begin
        if FCfg.QueryParamName = '' then Continue;
        V := R.QueryValue(FCfg.QueryParamName);
        if V <> '' then Exit(V);
      end;
    end;
  end;
end;

procedure TSessionManager.WriteSessionID(W: TResponseWriter; const ID: string;
  MaxAgeSec: integer; Expire: boolean);
var
  ExpiresDT: TDateTime;
begin
  if W = nil then Exit;

  // header
  if FCfg.HeaderName <> '' then
  begin
    if Expire then
      W.Header.DeleteKey(FCfg.HeaderName)
    else
      W.Header.SetValue(FCfg.HeaderName, ID);
  end;

  // cookie
  if FCfg.CookieName = '' then Exit;

  if Expire then
  begin
    ExpiresDT := IncSecond(NowUTC, -60);
    W.SetCookie(FCfg.CookieName, '', FCfg.CookiePath, FCfg.CookieDomain, ExpiresDT, 0,
      FCfg.CookieSecure, FCfg.CookieHTTPOnly, FCfg.CookieSameSite);
    Exit;
  end;

  if FCfg.CookieSessionOnly then
  begin
    W.SetCookie(FCfg.CookieName, ID, FCfg.CookiePath, FCfg.CookieDomain, 0, -1,
      FCfg.CookieSecure, FCfg.CookieHTTPOnly, FCfg.CookieSameSite);
  end
  else
  begin
    ExpiresDT := IncSecond(NowUTC, MaxAgeSec);
    W.SetCookie(FCfg.CookieName, ID, FCfg.CookiePath, FCfg.CookieDomain,
      ExpiresDT, MaxAgeSec,
      FCfg.CookieSecure, FCfg.CookieHTTPOnly, FCfg.CookieSameSite);
  end;
end;

function TSessionManager.TryGetRec(const ID: string; out Rec: TSessionRec): boolean;
  inline;
begin
  Result := FStore.Get(ID, Rec);
end;

procedure TSessionManager.PutRec(const ID: string; const Rec: TSessionRec); inline;
begin
  FStore.Insert(ID, Rec);
end;

function TSessionManager.RemoveRec(const ID: string; out Rec: TSessionRec): boolean;
  inline;
begin
  Result := FStore.Remove(ID, Rec);
end;

class function TSessionManager.CleanupIterator(const Key: string; const Value: TSessionRec; Context: Pointer): Boolean;
var
  C: ^TCleanupContext absolute Context;
  N: Integer;
begin
  Result := True;

  if C^.Mgr.IsExpired(Value, C^.NowDT) then
  begin
    N := Length(C^.ExpiredKeys);
    SetLength(C^.ExpiredKeys, N + 1);
    C^.ExpiredKeys[N] := Key;
  end;
end;

procedure TSessionManager.MaybeCleanup(const NowDT: TDateTime);
begin
  if (FLastCleanup = 0) or (SecondsBetween(NowDT, FLastCleanup) >=
    FCfg.CleanupIntervalSec) then
  begin
    Cleanup(NowDT);
    FLastCleanup := NowDT;
  end;
end;

procedure TSessionManager.Cleanup(const NowDT: TDateTime);
var
  Ctx: TCleanupContext;
  i: Integer;
  Dummy: TSessionRec;
begin
  Ctx.Mgr := Self;
  Ctx.NowDT := NowDT;
  SetLength(Ctx.ExpiredKeys, 0);

  FStore.Iterate(@CleanupIterator, @Ctx);

  for i := 0 to High(Ctx.ExpiredKeys) do
    FStore.Remove(Ctx.ExpiredKeys[i], Dummy);
end;

function TSessionManager.Get(W: TResponseWriter; R: TRequest): TSessionObj;
var
  ID: string;
  Rec: TSessionRec;
  NowDT: TDateTime;
  AbsExp: TDateTime;
begin
  Result := TSessionObj.Create;
  NowDT := NowUTC;

  ID := ReadSessionID(R);

  FLock.Enter;
  try
    MaybeCleanup(NowDT);

    if (ID <> '') and TryGetRec(ID, Rec) then
    begin
      if IsExpired(Rec, NowDT) then
      begin
        RemoveRec(ID, Rec);
        ID := '';
      end
      else
      begin
        Rec.ExpiresAt := MakeIdleTimeoutDT(NowDT);
        PutRec(ID, Rec);

        Result.FID := ID;
        Result.FData := Rec.Data;
        Result.FFresh := False;
        Result.FDestroyed := False;
        Result.FExpiresAt := Rec.ExpiresAt;
        Exit;
      end;
    end;

    // create new
    ID := NewID;
    Rec.ExpiresAt := MakeIdleTimeoutDT(NowDT);
    Rec.Data := Default(TData);

    // initialize abs-exp in data if enabled and accessor set
    if (FCfg.AbsoluteTimeoutSec > 0) and Assigned(FAbsSet) then
    begin
      AbsExp := MakeAbsTimeoutDT(NowDT);
      SetAbsExpToData(Rec.Data, AbsExp);
    end;

    PutRec(ID, Rec);

    Result.FID := ID;
    Result.FData := Rec.Data;
    Result.FFresh := True;
    Result.FDestroyed := False;
    Result.FExpiresAt := Rec.ExpiresAt;
  finally
    FLock.Leave;
  end;
end;

procedure TSessionManager.Save(W: TResponseWriter; const Sess: TSessionObj);
var
  NowDT: TDateTime;
  Rec: TSessionRec;
  AbsExp: TDateTime;
begin
  if (Sess = nil) or Sess.FDestroyed then Exit;
  if Sess.FID = '' then Exit;

  NowDT := NowUTC;

  FLock.Enter;
  try
    MaybeCleanup(NowDT);

    if not TryGetRec(Sess.FID, Rec) then
    begin
      Rec.Data := Default(TData);
      Rec.ExpiresAt := 0;
    end;

    // absolute expiration: if enabled and accessor exists, ensure it is set once
    if (FCfg.AbsoluteTimeoutSec > 0) and Assigned(FAbsSet) then
    begin
      if not GetAbsExpFromData(Sess.FData, AbsExp) or (AbsExp = 0) then
      begin
        AbsExp := MakeAbsTimeoutDT(NowDT);
        SetAbsExpToData(Sess.FData, AbsExp);
      end;
    end;

    Rec.ExpiresAt := MakeIdleTimeoutDT(NowDT);
    Rec.Data := Sess.FData;

    PutRec(Sess.FID, Rec);
    Sess.FExpiresAt := Rec.ExpiresAt;
  finally
    FLock.Leave;
  end;

  WriteSessionID(W, Sess.FID, FCfg.IdleTimeoutSec, False);
end;

procedure TSessionManager.DestroySession(W: TResponseWriter; const Sess: TSessionObj);
var
  Dummy: TSessionRec;
begin
  if Sess = nil then Exit;

  Sess.FDestroyed := True;

  if Sess.FID <> '' then
  begin
    FLock.Enter;
    try
      RemoveRec(Sess.FID, Dummy);
    finally
      FLock.Leave;
    end;
  end;

  WriteSessionID(W, '', 0, True);
end;

procedure TSessionManager.Regenerate(W: TResponseWriter; const Sess: TSessionObj;
  PreserveData: boolean);
var
  NowDT: TDateTime;
  OldID, NewIDStr: string;
  OldRec, NewRec: TSessionRec;
  AbsExp: TDateTime;
begin
  if (Sess = nil) or Sess.FDestroyed then Exit;

  NowDT := NowUTC;
  OldID := Sess.FID;
  NewIDStr := NewID;

  FLock.Enter;
  try
    MaybeCleanup(NowDT);

    if OldID <> '' then
      RemoveRec(OldID, OldRec);

    NewRec.ExpiresAt := MakeIdleTimeoutDT(NowDT);
    if PreserveData then
      NewRec.Data := Sess.FData
    else
      NewRec.Data := Default(TData);

    if (FCfg.AbsoluteTimeoutSec > 0) and Assigned(FAbsSet) then
    begin
      if not GetAbsExpFromData(NewRec.Data, AbsExp) or (AbsExp = 0) then
      begin
        AbsExp := MakeAbsTimeoutDT(NowDT);
        SetAbsExpToData(NewRec.Data, AbsExp);
        if PreserveData then
          Sess.FData := NewRec.Data;
      end;
    end;

    PutRec(NewIDStr, NewRec);

    Sess.FID := NewIDStr;
    Sess.FFresh := False;
    Sess.FExpiresAt := NewRec.ExpiresAt;
    if not PreserveData then
      Sess.FData := NewRec.Data;
  finally
    FLock.Leave;
  end;

  WriteSessionID(W, Sess.FID, FCfg.IdleTimeoutSec, False);
end;

procedure TSessionManager.Reset(W: TResponseWriter; const Sess: TSessionObj);
var
  NowDT: TDateTime;
  Dummy: TSessionRec;
  Rec: TSessionRec;
  AbsExp: TDateTime;
  OldID: string;
begin
  if (Sess = nil) or Sess.FDestroyed then Exit;

  NowDT := NowUTC;
  OldID := Sess.FID;

  FLock.Enter;
  try
    MaybeCleanup(NowDT);

    if OldID <> '' then
      RemoveRec(OldID, Dummy);

    Sess.FID := NewID;
    Sess.FFresh := True;
    Sess.FDestroyed := False;

    Rec.ExpiresAt := MakeIdleTimeoutDT(NowDT);
    Rec.Data := Default(TData);

    if (FCfg.AbsoluteTimeoutSec > 0) and Assigned(FAbsSet) then
    begin
      AbsExp := MakeAbsTimeoutDT(NowDT);
      SetAbsExpToData(Rec.Data, AbsExp);
    end;

    PutRec(Sess.FID, Rec);

    Sess.FData := Rec.Data;
    Sess.FExpiresAt := Rec.ExpiresAt;
  finally
    FLock.Leave;
  end;

  WriteSessionID(W, Sess.FID, FCfg.IdleTimeoutSec, False);
end;

function TSessionManager.Middleware(const Next: THandlerFunc;
  out GetSession: TGetSessionFunc): THandlerFunc;
var
  SelfPtr: Pointer;
begin
  SelfPtr := Self;

  GetSession := function(W: TResponseWriter; R: TRequest): TSessionObj
  begin
    Result := TSessionManager(SelfPtr).Get(W, R);
  end;

  Result := procedure(W: TResponseWriter; R: TRequest)
  var
    Sess: TSessionObj;
    Mgr: TSessionManager;
  begin
    Mgr := TSessionManager(SelfPtr);
    Sess := Mgr.Get(W, R);
    W.AddOnBeforeFinish(procedure(WW: TResponseWriter; RR: TRequest)
    begin
      if Sess <> nil then
      begin
        if Sess.Destroyed then  Mgr.DestroySession(WW, Sess)
        else
          Mgr.Save(WW, Sess);
      end;
    end);
    try
      Next(W, R);
    finally
      Sess.Free;
    end;
  end;

end;

end.
