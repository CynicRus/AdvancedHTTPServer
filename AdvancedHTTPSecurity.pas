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

unit AdvancedHTTPSecurity;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, DateUtils, StrUtils, syncobjs, fpjson, math,
  AdvancedHTTPServer, AdvancedHTTPRouter;

type
  TSecurityConfig = record
    // --- General behavior ---
    Enabled: boolean;
    PreferJSON: boolean;
    JSONErrorKey: string;

    // --- CSRF ---
    EnableCSRF: boolean;
    CSRFHeaderName: string;   // e.g. "X-CSRF-Token"
    CSRFCookieName: string;   // e.g. "csrf_token"
    CSRFTokenLength: integer; // e.g. 32
    CSRFSameSite: TResponseWriter.TCookieSameSite; // Lax/Strict
    CSRFSecureCookie: boolean; // set true on TLS
    RequireCSRFForMethods: TStringArray; // e.g. ['POST','PUT','PATCH','DELETE']
    // If true: for unsafe methods require Origin/Referer same-site (good baseline even without token)
    EnforceOriginForUnsafe: boolean;

    // --- Input validation / anti-XSS / anti-SQLi heuristics ---
    EnableInputChecks: boolean;
    MaxQueryBytes: integer;       // e.g. 4096
    MaxPathBytes: integer;        // e.g. 2048
    MaxHeaderValueBytes: integer; // e.g. 8192
    RejectSuspiciousPatterns: boolean;

    // --- Rate limiting (global per IP) ---
    EnableRateLimit: boolean;
    RateLimitRPS: double;     // tokens per second
    RateLimitBurst: double;   // bucket size
    RateLimitKeyBy: string;   // 'ip' or 'ip+ua'

    // --- Brute force (login endpoints) ---
    EnableBruteForce: boolean;
    LoginPathPrefixes: TStringArray; // e.g. ['/login','/auth/login']
    BruteMaxAttempts: integer;       // e.g. 10
    BruteWindowSeconds: integer;     // e.g. 300
    BruteBlockSeconds: integer;      // e.g. 900
    BruteTrackLoginField: string;    // e.g. 'username' or 'email' (in form/query/json best-effort)

    // --- Small allowlists / ignores ---
    SkipPathPrefixes: TStringArray; // e.g. ['/static/','/health']
  end;
  
type
  TTokenBucket = record
    Tokens: double;
    LastTS: int64; // ms
  end;

  TAttemptWindow = record
    Count: integer;
    WindowStartMS: int64;
    BlockUntilMS: int64;
  end;

  TSecurityState = class
  public
    Cfg: TSecurityConfig;

    Lock: TCriticalSection;

    // Rate limit: key -> bucket
    Rate: TStringList;

    // Brute: key -> packed "count|windowStart|blockUntil"
    Brute: TStringList;

    constructor Create(const ACfg: TSecurityConfig);
    destructor Destroy; override;

    function NowMS: int64;

    function ShouldSkipPath(const Path: string): boolean;

    function ClientKey(const R: TRequest): string;
    function ClientIP(const R: TRequest): string;

    // --- Error writers ---
    procedure WriteError(W: TResponseWriter; Code: integer; const Msg: string);
    procedure WriteJSONError(W: TResponseWriter; Code: integer; const Msg: string);

    // --- Checks ---
    function CheckInputBasics(W: TResponseWriter; R: TRequest): boolean;
    function CheckCSRF(W: TResponseWriter; R: TRequest): boolean;
    function CheckRateLimit(W: TResponseWriter; R: TRequest): boolean;

    function IsLoginPath(const Path: string): boolean;
    function ExtractLoginIdentity(R: TRequest): string;
    function CheckBruteForcePre(W: TResponseWriter; R: TRequest): boolean;
    procedure ObserveBruteForceResult(R: TRequest; StatusCode: integer);

    // Helpers
    function MethodInList(const M: string; const L: TStringArray): boolean;
    function LooksSuspicious(const S: string): boolean;
    function SameSiteByOriginOrReferer(const R: TRequest): boolean;
    function GetHostLower(const R: TRequest): string;
    function GetHeaderLower(const R: TRequest; const Name: string): string;
    function NewRandomTokenHex(LenBytes: integer): string;

    procedure EnsureCSRFCookie(W: TResponseWriter; R: TRequest);
  end;

function SecurityDefaultConfig: TSecurityConfig;

// Server middleware for server.Use(...)
function AdvancedSecurityMiddleware(const Cfg: TSecurityConfig): TMiddleware;

// Router middleware for router.Use(...)
function AdvancedSecurityRouterMiddleware(const Cfg: TSecurityConfig): TRouterMiddleware;

implementation



function SecurityDefaultConfig: TSecurityConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Enabled := True;
  Result.PreferJSON := True;
  Result.JSONErrorKey := 'error';

  Result.EnableCSRF := False;
  Result.CSRFHeaderName := 'X-CSRF-Token';
  Result.CSRFCookieName := 'csrf_token';
  Result.CSRFTokenLength := 32;
  Result.CSRFSameSite := TResponseWriter.TCookieSameSite.ssLax;
  Result.CSRFSecureCookie := True;
  Result.RequireCSRFForMethods := ['POST','PUT','PATCH','DELETE'];
  Result.EnforceOriginForUnsafe := True;

  Result.EnableInputChecks := True;
  Result.MaxQueryBytes := 4096;
  Result.MaxPathBytes := 2048;
  Result.MaxHeaderValueBytes := 8192;
  Result.RejectSuspiciousPatterns := True;

  Result.EnableRateLimit := True;
  Result.RateLimitRPS := 10.0;
  Result.RateLimitBurst := 20.0;
  Result.RateLimitKeyBy := 'ip';

  Result.EnableBruteForce := True;
  Result.LoginPathPrefixes := ['/login','/auth/login','/api/login','/api/auth/login'];
  Result.BruteMaxAttempts := 10;
  Result.BruteWindowSeconds := 300;
  Result.BruteBlockSeconds := 900;
  Result.BruteTrackLoginField := 'username';

  Result.SkipPathPrefixes := ['/static/','/health','/metrics'];
end;

{ TSecurityState }

constructor TSecurityState.Create(const ACfg: TSecurityConfig);
begin
  inherited Create;
  Cfg := ACfg;

  Lock := TCriticalSection.Create;

  Rate := TStringList.Create;
  Rate.CaseSensitive := False;
  Rate.NameValueSeparator := '=';
  Rate.Sorted := false;
  Rate.Duplicates := dupIgnore;

  Brute := TStringList.Create;
  Brute.CaseSensitive := False;
  Brute.NameValueSeparator := '=';
  Brute.Sorted := false;
  Brute.Duplicates := dupIgnore;
end;

destructor TSecurityState.Destroy;
begin
  Brute.Free;
  Rate.Free;
  Lock.Free;
  inherited Destroy;
end;

function TSecurityState.NowMS: int64;
begin
  Result := GetTickCount64;
end;

function TSecurityState.ShouldSkipPath(const Path: string): boolean;
var
  I: integer;
  P: string;
begin
  for I := 0 to High(Cfg.SkipPathPrefixes) do
  begin
    P := Cfg.SkipPathPrefixes[I];
    if (P <> '') and (LeftStr(Path, Length(P)) = P) then
      Exit(True);
  end;
  Result := False;
end;

function TSecurityState.ClientIP(const R: TRequest): string;
var
  P, L: SizeInt;
begin
  Result := Trim(R.RemoteAddr);
  if Result = '' then Exit('unknown');

  if (Length(Result) > 0) and (Result[1] = '[') then
  begin
    P := Pos(']', Result);
    if P > 0 then Exit(Copy(Result, 2, P-2));
  end;

  L := LastDelimiter(':', Result);
  if (L > 0) and (Pos(':', Copy(Result, 1, L-1)) = 0) then
    Result := Copy(Result, 1, L-1);
end;

function TSecurityState.ClientKey(const R: TRequest): string;
var
  IP, UA: string;
begin
  IP := ClientIP(R);
  if LowerCase(Cfg.RateLimitKeyBy) = 'ip+ua' then
  begin
    UA := R.Header.GetValue('User-Agent');
    if Length(UA) > 64 then UA := Copy(UA, 1, 64);
    Result := IP + '|' + UA;
  end
  else
    Result := IP;
end;

procedure TSecurityState.WriteJSONError(W: TResponseWriter; Code: integer; const Msg: string);
var
  Obj: TJSONObject;
begin
  if W.HeadersSent then Exit;
  Obj := TJSONObject.Create;
  try
    Obj.Add(Cfg.JSONErrorKey, Msg);
    W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
    W.WriteHeader(Code);
    W.Write(Obj.AsJSON);
  finally
    Obj.Free;
  end;
end;

procedure TSecurityState.WriteError(W: TResponseWriter; Code: integer; const Msg: string);
begin
  if Cfg.PreferJSON then
    WriteJSONError(W, Code, Msg)
  else
  begin
    if W.HeadersSent then Exit;
    W.Header.SetValue('Content-Type', 'text/plain; charset=utf-8');
    W.WriteHeader(Code);
    W.Write(Msg);
  end;
end;

function TSecurityState.MethodInList(const M: string; const L: TStringArray): boolean;
var
  I: integer;
begin
  for I := 0 to High(L) do
    if SameText(M, L[I]) then Exit(True);
  Result := False;
end;

function TSecurityState.LooksSuspicious(const S: string): boolean;
var
  L: string;
begin
  L := LowerCase(S);

  if Pos('<script', L) > 0 then Exit(True);
  if Pos('javascript:', L) > 0 then Exit(True);
  if Pos('onerror=', L) > 0 then Exit(True);
  if Pos('onload=', L) > 0 then Exit(True);

  if Pos(' union select ', L) > 0 then Exit(True);
  if Pos(' or 1=1', L) > 0 then Exit(True);
  if Pos(''' or ''', L) > 0 then Exit(True);
  if Pos('--', L) > 0 then Exit(True);
  if Pos('/*', L) > 0 then Exit(True);
  if Pos('*/', L) > 0 then Exit(True);
  if Pos('@@', L) > 0 then Exit(True);
  if Pos('information_schema', L) > 0 then Exit(True);

  Result := False;
end;

function TSecurityState.GetHeaderLower(const R: TRequest; const Name: string): string;
begin
  Result := LowerCase(Trim(R.Header.GetValue(Name)));
end;

function TSecurityState.GetHostLower(const R: TRequest): string;
var
  Parts: TAnsiStringArray;
begin
  Result := LowerCase(Trim(R.Header.GetValue('Host')));
  // strip port
  if Result <> '' then
  begin
    Parts := Result.Split([':']);
    if Length(Parts) > 0 then Result := Parts[0];
  end;
end;

function TSecurityState.SameSiteByOriginOrReferer(const R: TRequest): boolean;
var
  Host, O, Ref: string;

  function HostFromURLLower(const U: string): string;
  var
    P, SStart: SizeInt;
    Rest: string;
  begin
    Result := '';
    // very small parser: scheme://host[:port]/...
    P := Pos('://', U);
    if P <= 0 then Exit('');
    SStart := P + 3;
    Rest := Copy(U, SStart, MaxInt);
    // trim path
    P := Pos('/', Rest);
    if P > 0 then Rest := Copy(Rest, 1, P-1);
    Rest := LowerCase(Trim(Rest));
    // strip port (but keep ipv6 bracket form)
    if (Rest <> '') and (Rest[1] = '[') then
    begin
      P := Pos(']', Rest);
      if P > 0 then Exit(Copy(Rest, 2, P-2));
    end;
    P := LastDelimiter(':', Rest);
    if (P > 0) and (Pos(':', Copy(Rest, 1, P-1)) = 0) then
      Rest := Copy(Rest, 1, P-1);
    Result := Rest;
  end;

begin
  Host := GetHostLower(R);
  if Host = '' then Exit(False);

  O := Trim(R.Header.GetValue('Origin'));
  if O <> '' then
    Exit(HostFromURLLower(O) = Host);

  Ref := Trim(R.Header.GetValue('Referer'));
  if Ref <> '' then
    Exit(HostFromURLLower(Ref) = Host);

  // If neither Origin nor Referer present:
  // For browsers, unsafe cross-site requests usually include at least Origin.
  // But not always. We'll treat as failure if enforcing.
  Result := False;
end;

function TSecurityState.NewRandomTokenHex(LenBytes: integer): string;
var
  I: integer;
  B: byte;
begin
  Result := '';
  if LenBytes <= 0 then Exit;
  // NOTE: Random() is not cryptographically secure.
  // For serious use, replace with OS CSPRNG.
  for I := 1 to LenBytes do
  begin
    B := byte(Random(256));
    Result := Result + IntToHex(B, 2);
  end;
end;

procedure TSecurityState.EnsureCSRFCookie(W: TResponseWriter; R: TRequest);
var
  Tok: string;
  Secure: boolean;
begin
  if not Cfg.EnableCSRF then Exit;
  if Cfg.CSRFCookieName = '' then Exit;

  Tok := R.CookieValue(Cfg.CSRFCookieName);
  if Tok = '' then
  begin
    Tok := NewRandomTokenHex(Cfg.CSRFTokenLength);
    // Secure cookie: set on TLS (or forced)
    Secure := Cfg.CSRFSecureCookie and R.TLS;
    W.SetCookie(Cfg.CSRFCookieName, Tok, '/', '', 0, -1, Secure, True, Cfg.CSRFSameSite);
  end;
end;

function TSecurityState.CheckCSRF(W: TResponseWriter; R: TRequest): boolean;
var
  Need: boolean;
  CookieTok, HeaderTok: string;
begin
  Result := True;
  if not Cfg.EnableCSRF then Exit(True);

  Need := MethodInList(R.Method, Cfg.RequireCSRFForMethods);
  if not Need then
  begin
    // Still can issue cookie for clients
    EnsureCSRFCookie(W, R);
    Exit(True);
  end;

  // Optional origin enforcement for unsafe methods
  if Cfg.EnforceOriginForUnsafe then
  begin
    if not SameSiteByOriginOrReferer(R) then
    begin
      WriteError(W, 403, 'CSRF check failed');
      Exit(False);
    end;
  end;

  // Double-submit cookie: Cookie must equal header
  CookieTok := R.CookieValue(Cfg.CSRFCookieName);
  HeaderTok := R.Header.GetValue(Cfg.CSRFHeaderName);

  if (CookieTok = '') or (HeaderTok = '') or (CookieTok <> HeaderTok) then
  begin
    WriteError(W, 403, 'CSRF token missing or invalid');
    Exit(False);
  end;

  Result := True;
end;

function TSecurityState.CheckInputBasics(W: TResponseWriter; R: TRequest): boolean;
var
  I: integer;
  V: string;
  Q,F: TStringList;
begin
  Result := True;
  if not Cfg.EnableInputChecks then Exit(True);

  if (Cfg.MaxPathBytes > 0) and (Length(R.Path) > Cfg.MaxPathBytes) then
  begin
    WriteError(W, 414, 'Path too long');
    Exit(False);
  end;

  if (Cfg.MaxQueryBytes > 0) and (Length(R.RawQuery) > Cfg.MaxQueryBytes) then
  begin
    WriteError(W, 414, 'Query too long');
    Exit(False);
  end;

  // Header value length cap (best-effort)
  for I := 0 to R.Header.Count - 1 do
  begin
    V := R.Header.ValueFromIndex[I];
    if (Cfg.MaxHeaderValueBytes > 0) and (Length(V) > Cfg.MaxHeaderValueBytes) then
    begin
      WriteError(W, 431, 'Request header too large');
      Exit(False);
    end;
  end;

  if Cfg.RejectSuspiciousPatterns then
  begin
    if LooksSuspicious(R.Path) or LooksSuspicious(R.RawQuery) then
    begin
      WriteError(W, 400, 'Bad request');
      Exit(False);
    end;
    try
      R.ParseQuery(Q);
      for I := 0 to Q.Count - 1 do
        if LooksSuspicious(Q.ValueFromIndex[I]) then
        begin
          WriteError(W, 400, 'Bad request');
          Exit(False);
        end;

      R.ParsePostForm(F);
      for I := 0 to F.Count - 1 do
        if LooksSuspicious(F.ValueFromIndex[I]) then
        begin
          WriteError(W, 400, 'Bad request');
          Exit(False);
        end;
    finally
      if Assigned(Q) then Q.Free;
      if Assigned(F) then F.Free;
    end;
  end;
end;

function TSecurityState.CheckRateLimit(W: TResponseWriter; R: TRequest): boolean;
var
  Key: string;
  Idx: integer;
  B: TTokenBucket;
  vNowMs: int64;
  Elapsed: double;
  S: string;

  function ParseBucket(const Raw: string; out BB: TTokenBucket): boolean;
  var
    Parts: TStringArray;
  begin
    FillChar(BB, SizeOf(BB), 0);
    Parts := Raw.Split(['|']);
    if Length(Parts) <> 2 then Exit(False);
    BB.Tokens := StrToFloatDef(Parts[0], 0);
    BB.LastTS := StrToInt64Def(Parts[1], 0);
    Result := True;
  end;

  function PackBucket(const BB: TTokenBucket): string;
  begin
    Result := FloatToStr(BB.Tokens) + '|' + IntToStr(BB.LastTS);
  end;

begin
  Result := True;
  if not Cfg.EnableRateLimit then Exit(True);
  if (Cfg.RateLimitRPS <= 0) or (Cfg.RateLimitBurst <= 0) then Exit(True);

  Key := ClientKey(R);
  vNowMs := NowMS;

  Lock.Enter;
  try
    Idx := Rate.IndexOfName(Key);
    if Idx < 0 then
    begin
      B.Tokens := Cfg.RateLimitBurst;
      B.LastTS := vNowMs;
      Rate.Values[Key] := PackBucket(B);
      Exit(True);
    end;

    S := Rate.ValueFromIndex[Idx];
    if not ParseBucket(S, B) then
    begin
      B.Tokens := Cfg.RateLimitBurst;
      B.LastTS := vNowMs;
    end;

    Elapsed := (NowMs - B.LastTS) / 1000.0;
    if Elapsed < 0 then Elapsed := 0;

    B.Tokens := Min(Cfg.RateLimitBurst, B.Tokens + Elapsed * Cfg.RateLimitRPS);
    B.LastTS := vNowMs;

    if B.Tokens < 1.0 then
    begin
      Rate.ValueFromIndex[Idx] := PackBucket(B);
      // Optional: Retry-After
      if not W.HeadersSent then
        W.Header.SetValue('Retry-After', '1');
      WriteError(W, 429, 'Too Many Requests');
      Exit(False);
    end;

    B.Tokens := B.Tokens - 1.0;
    Rate.ValueFromIndex[Idx] := PackBucket(B);
  finally
    Lock.Leave;
  end;

  Result := True;
end;

function TSecurityState.IsLoginPath(const Path: string): boolean;
var
  I: integer;
  P: string;
begin
  for I := 0 to High(Cfg.LoginPathPrefixes) do
  begin
    P := Cfg.LoginPathPrefixes[I];
    if (P <> '') and (LeftStr(Path, Length(P)) = P) then
      Exit(True);
  end;
  Result := False;
end;

function TSecurityState.ExtractLoginIdentity(R: TRequest): string;
var
  K: string;
  CT, Body: string;
  J: TJSONData;
begin
  Result := '';
  K := Cfg.BruteTrackLoginField;
  if K = '' then Exit('');

  // Try form first
  Result := Trim(R.PostFormValue(K));
  if Result <> '' then Exit;

  // Then query (some APIs do this)
  Result := Trim(R.QueryValue(K));
  if Result <> '' then Exit;

  // Best-effort JSON extraction (only if body looks like JSON object)
  // Avoid heavy parsing for huge bodies
  CT := LowerCase(R.Header.GetValue('Content-Type'));
  if Pos('application/json', CT) <= 0 then Exit('');

  Body := Trim(R.BodyUTF8);
  if (Body = '') or (Length(Body) > 1024*64) then Exit('');
  if (Body[1] <> '{') then Exit('');

  try
    J := GetJSON(Body);
    try
      if (J <> nil) and (J.JSONType = jtObject) then
        Result := Trim(TJSONObject(J).Get(K, ''));
    finally
      J.Free;
    end;
  except
    // ignore json parse errors
  end;
end;

function TSecurityState.CheckBruteForcePre(W: TResponseWriter; R: TRequest): boolean;
var
  Key, IP, Ident: string;
  Idx: integer;
  vNowMs: int64;
  Raw: string;
  Parts: TStringArray;
  A: TAttemptWindow;
begin
  Result := True;
  if not Cfg.EnableBruteForce then Exit(True);
  if not IsLoginPath(R.Path) then Exit(True);
  if not SameText(R.Method, 'POST') then Exit(True);

  IP := ClientIP(R);
  Ident := ExtractLoginIdentity(R);
  if Ident <> '' then
    Key := 'login|' + LowerCase(Ident) + '|' + IP
  else
    Key := 'login|_noid_|' + IP;

  vNowMs := NowMS;

  Lock.Enter;
  try
    Idx := Brute.IndexOfName(Key);
    FillChar(A, SizeOf(A), 0);

    if Idx >= 0 then
    begin
      Raw := Brute.ValueFromIndex[Idx];
      Parts := Raw.Split(['|']);
      if Length(Parts) = 3 then
      begin
        A.Count := StrToIntDef(Parts[0], 0);
        A.WindowStartMS := StrToInt64Def(Parts[1], vNowMs);
        A.BlockUntilMS := StrToInt64Def(Parts[2], 0);
      end;
    end
    else
    begin
      A.Count := 0;
      A.WindowStartMS := vNowMs;
      A.BlockUntilMS := 0;
    end;

    if (A.BlockUntilMS > 0) and (NowMs < A.BlockUntilMS) then
    begin
      if not W.HeadersSent then
        W.Header.SetValue('Retry-After', IntToStr((A.BlockUntilMS - vNowMs) div 1000));
      WriteError(W, 429, 'Too Many Requests');
      Exit(False);
    end;

    // Window reset
    if (Cfg.BruteWindowSeconds > 0) and (vNowMs - A.WindowStartMS > int64(Cfg.BruteWindowSeconds) * 1000) then
    begin
      A.Count := 0;
      A.WindowStartMS := NowMs;
      A.BlockUntilMS := 0;
    end;

    // Save back (pre state)
    if Idx < 0 then
      Brute.Values[Key] := IntToStr(A.Count) + '|' + IntToStr(A.WindowStartMS) + '|' + IntToStr(A.BlockUntilMS)
    else
      Brute.ValueFromIndex[Idx] := IntToStr(A.Count) + '|' + IntToStr(A.WindowStartMS) + '|' + IntToStr(A.BlockUntilMS);
  finally
    Lock.Leave;
  end;
end;

procedure TSecurityState.ObserveBruteForceResult(R: TRequest; StatusCode: integer);
var
  Key, IP, Ident: string;
  Idx: integer;
  vNowMs: int64;
  Raw: string;
  Parts: TStringArray;
  A: TAttemptWindow;

  procedure Save;
  begin
    if Idx < 0 then
      Brute.Values[Key] := IntToStr(A.Count) + '|' + IntToStr(A.WindowStartMS) + '|' + IntToStr(A.BlockUntilMS)
    else
      Brute.ValueFromIndex[Idx] := IntToStr(A.Count) + '|' + IntToStr(A.WindowStartMS) + '|' + IntToStr(A.BlockUntilMS);
  end;

begin
  if not Cfg.EnableBruteForce then Exit;
  if not IsLoginPath(R.Path) then Exit;
  if not SameText(R.Method, 'POST') then Exit;

  // Count only failures (401/403) and maybe 400 (bad creds vs bad request - depends)
  if not ((StatusCode = 401) or (StatusCode = 403)) then Exit;

  IP := ClientIP(R);
  Ident := ExtractLoginIdentity(R);
  if Ident <> '' then
    Key := 'login|' + LowerCase(Ident) + '|' + IP
  else
    Key := 'login|_noid_|' + IP;

  vNowMs := NowMS;

  Lock.Enter;
  try
    Idx := Brute.IndexOfName(Key);
    FillChar(A, SizeOf(A), 0);

    if Idx >= 0 then
    begin
      Raw := Brute.ValueFromIndex[Idx];
      Parts := Raw.Split(['|']);
      if Length(Parts) = 3 then
      begin
        A.Count := StrToIntDef(Parts[0], 0);
        A.WindowStartMS := StrToInt64Def(Parts[1], vNowMs);
        A.BlockUntilMS := StrToInt64Def(Parts[2], 0);
      end;
    end
    else
    begin
      A.Count := 0;
      A.WindowStartMS := vNowMs;
      A.BlockUntilMS := 0;
    end;

    // Window reset
    if (Cfg.BruteWindowSeconds > 0) and (NowMs - A.WindowStartMS > int64(Cfg.BruteWindowSeconds) * 1000) then
    begin
      A.Count := 0;
      A.WindowStartMS := NowMs;
      A.BlockUntilMS := 0;
    end;

    Inc(A.Count);

    if (Cfg.BruteMaxAttempts > 0) and (A.Count >= Cfg.BruteMaxAttempts) then
    begin
      if Cfg.BruteBlockSeconds > 0 then
        A.BlockUntilMS := vNowMs + int64(Cfg.BruteBlockSeconds) * 1000
      else
        A.BlockUntilMS := vNowMs + 60*1000;
    end;

    Save;
  finally
    Lock.Leave;
  end;
end;

function AdvancedSecurityMiddleware(const Cfg: TSecurityConfig): TMiddleware;
var
  State: TSecurityState;
begin
  Randomize;
  State := TSecurityState.Create(Cfg);

  Result := function(Next: THandlerFunc): THandlerFunc
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    begin
      if (not State.Cfg.Enabled) or State.ShouldSkipPath(R.Path) then
      begin
        Next(W, R);
        Exit;
      end;

      // Rate limit first (cheap)
      if not State.CheckRateLimit(W, R) then Exit;

      // Input checks
      if not State.CheckInputBasics(W, R) then Exit;

      // Brute-force gate (pre)
      if not State.CheckBruteForcePre(W, R) then Exit;

      // CSRF (unsafe methods)
      if not State.CheckCSRF(W, R) then Exit;

      // Observe result for brute-force after handler runs
      // Use OnBeforeFinish hook to read final status.
      W.OnBeforeFinish := procedure(WW: TResponseWriter; RR: TRequest)
      begin
        State.ObserveBruteForceResult(RR, WW.StatusCode);
      end;

      Next(W, R);
    end;
  end;
end;

function AdvancedSecurityRouterMiddleware(const Cfg: TSecurityConfig): TRouterMiddleware;
var
  State: TSecurityState;
begin
  Randomize;
  State := TSecurityState.Create(Cfg);

  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
  begin
    Ctx := THTTPRouterContext(C);

    if (not State.Cfg.Enabled) or State.ShouldSkipPath(Ctx.R.Path) then
    begin
      Ctx.Next;
      Exit;
    end;

    if not State.CheckRateLimit(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    if not State.CheckInputBasics(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    if not State.CheckBruteForcePre(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    if not State.CheckCSRF(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    Ctx.W.OnBeforeFinish := procedure(WW: TResponseWriter; RR: TRequest)
    begin
      State.ObserveBruteForceResult(RR, WW.StatusCode);
    end;

    Ctx.Next;
  end;
end;

end.
