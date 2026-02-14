{
  Copyright (c) 2026 Aleksandr Vorobev aka CynicRus, CynicRus@gmail.com

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  3. Neither the name of the copyright holder nor the names of its
     contributors may be used to endorse or promote products derived from
     this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
}

unit AdvancedHTTPCache;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, DateUtils, StrUtils, syncobjs,
  AdvancedHTTPServer, AdvancedHTTPRouter,
  HashMap;

type
  TCacheAcceptVariant = (cavAny, cavJSON);

  THTTPCacheConfig = record
    Enabled: boolean;

    // TTL
    DefaultTTLSeconds: integer;     // 0 => don't cache unless handler set Cache-Control max-age (not implemented here)
    MaxEntryBytes: integer;         // protect memory (0 => unlimited)
    MaxEntries: integer;            // 0 => unlimited (but consider periodic purge)

    // What to cache
    CacheStatuses: array of integer;   // default [200,204,301,404]
    CacheMethods: TStringArray;        // default ['GET','HEAD']
    IncludeQuery: boolean;             // default True

    // Key behavior
    UseRoutePattern: boolean;          // default True (fallback to R.Path)
    VaryByOrigin: boolean;             // default True (safe with reflective CORS)
    VaryByAcceptJSON: boolean;         // default True (separate JSON/non-JSON by Accept)

    // ETag behavior
    EnableETag: boolean;               // default True
    WeakETag: boolean;                 // default True => W/"..."
    AddCacheHeaders: boolean;          // default True => Cache-Control, ETag, etc.

    // Debug header
    AddXCacheHeader: boolean;          // default True: HIT/MISS/REVALIDATED
  end;

type
  TCacheEntry = record
    Status: integer;
    CreatedAtUTC: TDateTime;
    ExpiresAtUTC: TDateTime;

    // minimal headers to replay
    ContentType: string;
    Location: string;

    // entity headers
    ETag: string;

    // body
    Body: ansistring;
  end;

  TCacheState = class
  public
    Router: THTTPRouter;
    Cfg: THTTPCacheConfig;
    Lock: TCriticalSection;
    Map: specialize TStringHashMap<TCacheEntry>;

    constructor Create(ARouter: THTTPRouter; const ACfg: THTTPCacheConfig);
    destructor Destroy; override;

    function NowUTC: TDateTime; inline;

    function MethodAllowed(const M: string): boolean;
    function StatusAllowed(Code: integer): boolean;

    function AcceptVariant(const R: TRequest): TCacheAcceptVariant;
    function AcceptVariantKey(const V: TCacheAcceptVariant): string;

    function BuildKey(const Ctx: THTTPRouterContext): string;

    function TryGetFresh(const Key: string; out E: TCacheEntry): boolean;
    procedure PutOrReplace(const Key: string; const E: TCacheEntry);

    procedure PurgeExpiredLocked; // optional simple purge when size too big
  end;

function CacheDefaultConfig: THTTPCacheConfig;

// Router middleware for router.Use(...)
function CacheRouterMiddleware(const Router: THTTPRouter; const Cfg: THTTPCacheConfig): TRouterMiddleware;

implementation


function CacheDefaultConfig: THTTPCacheConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Enabled := True;

  Result.DefaultTTLSeconds := 30;
  Result.MaxEntryBytes := 1024*1024; // 1MB default safety
  Result.MaxEntries := 5000;

  Result.CacheStatuses := [200,204,301,404];
  Result.CacheMethods := ['GET','HEAD'];
  Result.IncludeQuery := True;

  Result.UseRoutePattern := True;
  Result.VaryByOrigin := True;
  Result.VaryByAcceptJSON := True;

  Result.EnableETag := True;
  Result.WeakETag := True;
  Result.AddCacheHeaders := True;

  Result.AddXCacheHeader := True;
end;

function HasTokenCI(const Haystack, Needle: string): boolean;
var
  H, N: string;
begin
  H := LowerCase(Haystack);
  N := LowerCase(Needle);
  Result := Pos(N, H) > 0;
end;

function TrimLower(const S: string): string; inline;
begin
  Result := LowerCase(Trim(S));
end;

function QuoteETag(const S: string): string;
begin
  // Ensure it's quoted. If already quoted, keep.
  if S = '' then Exit('');
  if (Length(S) >= 2) and (S[1] = '"') and (S[Length(S)] = '"') then Exit(S);
  Result := '"' + S + '"';
end;

function NormalizeETag(const S: string): string;
begin
  // for comparisons (weak/strong treated same here for simplicity)
  Result := Trim(S);
  // strip W/ prefix
  if (Length(Result) >= 2) and ((Result[1] = 'W') or (Result[1] = 'w')) and (Result[2] = '/') then
    Result := Trim(Copy(Result, 3, MaxInt));
  Result := Trim(Result);
end;

function IfNoneMatchMatches(const IfNoneMatch, ETag: string): boolean;
var
  INM: string;
  Parts: TStringArray;
  I: integer;
  Token: string;
begin
  INM := Trim(IfNoneMatch);
  if INM = '' then Exit(False);

  // "*" matches any current representation
  if INM = '*' then Exit(True);

  Parts := INM.Split([',']);
  for I := 0 to High(Parts) do
  begin
    Token := Trim(Parts[I]);
    if NormalizeETag(Token) = NormalizeETag(ETag) then
      Exit(True);
  end;

  Result := False;
end;

function SimpleFNV1a32(const S: ansistring): longword;
var
  I: SizeInt;
  B: byte;
begin
  Result := $811C9DC5;
  for I := 1 to Length(S) do
  begin
    B := byte(S[I]);
    Result := (Result xor B) * $01000193;
  end;
end;

function BuildETagFromBody(const Body: ansistring; Weak: boolean): string;
var
  H: longword;
  T: string;
begin
  H := SimpleFNV1a32(Body);
  // Include length to reduce trivial collisions a bit
  T := IntToHex(H, 8) + '-' + IntToHex(Length(Body), 8);
  if Weak then
    Result := 'W/' + QuoteETag(T)
  else
    Result := QuoteETag(T);
end;

procedure AppendVaryHeader(H: THeader; const V: string);
var
  CurL, VL: string;
begin
  VL := LowerCase(V);
  CurL := LowerCase(H.GetValue('Vary'));
  if CurL = '' then
    H.SetValue('Vary', V)
  else if Pos(VL, CurL) = 0 then
    H.SetValue('Vary', H.GetValue('Vary') + ', ' + V);
end;

{ TCacheState }

constructor TCacheState.Create(ARouter: THTTPRouter; const ACfg: THTTPCacheConfig);
begin
  inherited Create;
  Router := ARouter;
  Cfg := ACfg;
  Lock := TCriticalSection.Create;
  Map := specialize TStringHashMap<TCacheEntry>.Create;
  Map.Reserve(ACfg.MaxEntries);
end;

destructor TCacheState.Destroy;
begin
  Map.Free;
  Lock.Free;
  inherited Destroy;
end;

function TCacheState.NowUTC: TDateTime; inline;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

function TCacheState.MethodAllowed(const M: string): boolean;
var
  I: integer;
begin
  for I := 0 to High(Cfg.CacheMethods) do
    if SameText(M, Cfg.CacheMethods[I]) then Exit(True);
  Result := False;
end;

function TCacheState.StatusAllowed(Code: integer): boolean;
var
  I: integer;
begin
  for I := 0 to High(Cfg.CacheStatuses) do
    if Code = Cfg.CacheStatuses[I] then Exit(True);
  Result := False;
end;

function TCacheState.AcceptVariant(const R: TRequest): TCacheAcceptVariant;
var
  A: string;
begin
  if not Cfg.VaryByAcceptJSON then Exit(cavAny);

  A := TrimLower(R.Header.GetValue('Accept'));
  // If Accept is empty, most clients accept anything => treat as "any"
  if A = '' then Exit(cavAny);

  // If client explicitly accepts JSON (or wildcard types that include it), cache JSON variant
  if (Pos('application/json', A) > 0) or (Pos('*/json', A) > 0) then
    Exit(cavJSON);

  // Also: "*/*" means "any", but we don't want to pollute both variants;
  // keep it as cavAny.
  Result := cavAny;
end;

function TCacheState.AcceptVariantKey(const V: TCacheAcceptVariant): string;
begin
  case V of
    cavJSON: Result := 'accept=json';
    else    Result := 'accept=any';
  end;
end;

function TCacheState.BuildKey(const Ctx: THTTPRouterContext): string;
var
  RouteKey, Q, Origin, M: string;
begin
  M := UpperCase(Ctx.R.Method);

  if Cfg.UseRoutePattern and (Ctx.RoutePattern <> '') then
    RouteKey := Ctx.RoutePattern
  else if Assigned(Router) then
    RouteKey := Router.NormalizePath(Ctx.R.Path)
  else
    RouteKey := Ctx.R.Path;

  if Cfg.IncludeQuery and (Ctx.R.RawQuery <> '') then
    Q := '?' + Ctx.R.RawQuery
  else
    Q := '';

  // Vary by Accept(JSON) or not
  Result := M + '|' + RouteKey + Q + '|' + AcceptVariantKey(AcceptVariant(Ctx.R));

  // Vary by Origin for reflective CORS safety (Cors middleware adds Vary: Origin)
  if Cfg.VaryByOrigin then
  begin
    Origin := TrimLower(Ctx.R.Header.GetValue('Origin'));
    if Origin <> '' then
      Result := Result + '|origin=' + Origin
    else
      Result := Result + '|origin=';
  end;
end;

function TCacheState.TryGetFresh(const Key: string; out E: TCacheEntry): boolean;
var
  NowU: TDateTime;
begin
  Result := False;
  NowU := NowUTC;

  Lock.Enter;
  try
    if not Map.Get(Key, E) then Exit(False);
    if (E.ExpiresAtUTC > 0) and (NowU >= E.ExpiresAtUTC) then
      Exit(False);
    Result := True;
  finally
    Lock.Leave;
  end;
end;

type
  TCachePurgeCtx = record
    NowU: TDateTime;
    RemoveKeys: array of string;
  end;
  PCachePurgeCtx = ^TCachePurgeCtx;

function CachePurgeCB(const K: string; const V: TCacheEntry; Ctx: Pointer): boolean;
var
  C: PCachePurgeCtx;
  N: SizeInt;
begin
  C := PCachePurgeCtx(Ctx);

  // remove if expired
  if (V.ExpiresAtUTC > 0) and (C^.NowU >= V.ExpiresAtUTC) then
  begin
    N := Length(C^.RemoveKeys);
    SetLength(C^.RemoveKeys, N + 1);
    C^.RemoveKeys[N] := K;
  end;

  Result := True;
end;

procedure TCacheState.PurgeExpiredLocked;
var
  Ctx: TCachePurgeCtx;
  I: Integer;
begin
  Ctx.NowU := NowUTC;
  SetLength(Ctx.RemoveKeys, 0);

  Map.Iterate(@CachePurgeCB, @Ctx);

  for I := 0 to High(Ctx.RemoveKeys) do
    Map.Remove(Ctx.RemoveKeys[I]);
end;

procedure TCacheState.PutOrReplace(const Key: string; const E: TCacheEntry);
var
  Dummy: TCacheEntry;
begin
  Lock.Enter;
  try
    // keep map bounded (very simple strategy)
    if (Cfg.MaxEntries > 0) and (Map.Size >= SizeUInt(Cfg.MaxEntries)) then
      PurgeExpiredLocked;

    if (Cfg.MaxEntries > 0) and (Map.Size >= SizeUInt(Cfg.MaxEntries)) then
    begin
      // remove this key if exists then insert (no growth), otherwise just remove nothing
      Map.Remove(Key, Dummy);
    end;

    Map.Insert(Key, E);
  finally
    Lock.Leave;
  end;
end;

procedure WriteCachedResponse(W: TResponseWriter; const E: TCacheEntry; const Cfg: THTTPCacheConfig);
var
  TTL: integer;
  NowU: TDateTime;
begin
  if W.HeadersSent then Exit;

  // Minimal replay of important headers
  if E.ContentType <> '' then
    W.Header.SetValue('Content-Type', E.ContentType);

  if (E.Status = 301) and (E.Location <> '') then
    W.Header.SetValue('Location', E.Location);

  if Cfg.AddCacheHeaders then
  begin
    // ETag
    if Cfg.EnableETag and (E.ETag <> '') then
      W.Header.SetValue('ETag', E.ETag);

    // Cache-Control: public, max-age=...
    NowU := TTimeZone.Local.ToUniversalTime(Now);
    if (E.ExpiresAtUTC > 0) and (E.ExpiresAtUTC > NowU) then
    begin
      TTL := SecondsBetween(E.ExpiresAtUTC, NowU);
      if TTL < 0 then TTL := 0;
      W.Header.SetValue('Cache-Control', 'public, max-age=' + IntToStr(TTL));
    end
    else
      W.Header.SetValue('Cache-Control', 'public, max-age=0');
  end;

  W.WriteHeader(E.Status);

  if (E.Status <> 204) and (Length(E.Body) > 0) then
    W.Write(string(E.Body));
end;

function CacheRouterMiddleware(const Router: THTTPRouter; const Cfg: THTTPCacheConfig): TRouterMiddleware;
var
  State: TCacheState;
begin
  State := TCacheState.Create(Router, Cfg);

  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    Key: string;
    Entry: TCacheEntry;
    IfNoneMatch: string;
  begin
    Ctx := THTTPRouterContext(C);

    if not State.Cfg.Enabled then
    begin
      Ctx.Next;
      Exit;
    end;

    if not State.MethodAllowed(Ctx.R.Method) then
    begin
      Ctx.Next;
      Exit;
    end;

    Key := State.BuildKey(Ctx);

    // Try HIT (fresh)
    if State.TryGetFresh(Key, Entry) then
    begin
      if State.Cfg.AddXCacheHeader and (not Ctx.W.HeadersSent) then
        Ctx.W.Header.SetValue('X-Cache', 'HIT');

      // If-None-Match => 304
      if State.Cfg.EnableETag and (Entry.ETag <> '') then
      begin
        IfNoneMatch := Ctx.R.Header.GetValue('If-None-Match');
        if IfNoneMatchMatches(IfNoneMatch, Entry.ETag) then
        begin
          // 304 must not include body
          if not Ctx.W.HeadersSent then
          begin
            Ctx.W.Header.SetValue('ETag', Entry.ETag);
            Ctx.W.Header.SetValue('Cache-Control', Ctx.W.Header.GetValue('Cache-Control')); // keep if any
            Ctx.W.WriteHeader(304);
          end;
          Ctx.Abort;
          Exit;
        end;
      end;

      WriteCachedResponse(Ctx.W, Entry, State.Cfg);
      Ctx.Abort;
      Exit;
    end;

    // MISS => continue, and capture in OnBeforeFinish
    if State.Cfg.AddXCacheHeader and (not Ctx.W.HeadersSent) then
      Ctx.W.Header.SetValue('X-Cache', 'MISS');

    // Ensure Vary is correct with our keying (good practice)
    if State.Cfg.VaryByOrigin then
      AppendVaryHeader(Ctx.W.Header, 'Origin');
    if State.Cfg.VaryByAcceptJSON then
      AppendVaryHeader(Ctx.W.Header, 'Accept');

    Ctx.W.OnBeforeFinish := procedure(WW: TResponseWriter; RR: TRequest)
    var
      E: TCacheEntry;
      BodyBuf: ansistring;
      TTL: integer;
      NowU: TDateTime;
      CT: string;
      Loc: string;
    begin
      // Only cache allowed statuses
      if not State.StatusAllowed(WW.StatusCode) then Exit;

      // Only cache buffered responses (in this server by default yes)
      BodyBuf := WW.BufferedBody;

      // Enforce size limit
      if (State.Cfg.MaxEntryBytes > 0) and (Length(BodyBuf) > State.Cfg.MaxEntryBytes) then
        Exit;

      TTL := State.Cfg.DefaultTTLSeconds;
      if TTL <= 0 then Exit;

      NowU := State.NowUTC;

      FillChar(E, SizeOf(E), 0);
      E.Status := WW.StatusCode;
      E.CreatedAtUTC := NowU;
      E.ExpiresAtUTC := IncSecond(NowU, TTL);

      // store minimal headers
      CT := WW.Header.GetValue('Content-Type');
      if CT <> '' then E.ContentType := CT;

      if WW.StatusCode = 301 then
      begin
        Loc := WW.Header.GetValue('Location');
        if Loc <> '' then E.Location := Loc;
      end;

      // body
      E.Body := BodyBuf;

      // ETag
      if State.Cfg.EnableETag then
      begin
        // if handler already set ETag, keep it
        E.ETag := WW.Header.GetValue('ETag');
        if E.ETag = '' then
          E.ETag := BuildETagFromBody(E.Body, State.Cfg.WeakETag);

        // also ensure response has ETag for the current request (MISS but cacheable)
        if (not WW.HeadersSent) and (WW.Header.GetValue('ETag') = '') then
          WW.Header.SetValue('ETag', E.ETag);
      end;

      // Cache-Control to client
      if State.Cfg.AddCacheHeaders and (not WW.HeadersSent) then
        WW.Header.SetValue('Cache-Control', 'public, max-age=' + IntToStr(TTL));

      // Mark header as stored
      if State.Cfg.AddXCacheHeader and (not WW.HeadersSent) then
        WW.Header.SetValue('X-Cache', 'STORE');

      // Put to cache
      State.PutOrReplace(Key, E);
    end;

    Ctx.Next;
  end;
end;

end.
