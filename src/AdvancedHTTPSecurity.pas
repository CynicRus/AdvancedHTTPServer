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
  {$IFDEF MSWINDOWS}
   jwawincrypt,
  {$ENDIF}
  {$IFDEF UNIX}
   BaseUnix,
  {$ENDIF}
  SysUtils, Classes, DateUtils, StrUtils, syncobjs, fpjson, math,
  AdvancedHTTPServer, AdvancedHTTPRouter,
  HashMap;

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
    CSRFSameSite: TResponseWriter.TCookieSameSite; // Lax/Strict/None
    CSRFSecureCookie: boolean; // set true on TLS
    CSRFTrustedOrigins: TStringArray; // e.g. ['https://app.example.com', 'https://*.example.com']
    CSRFCookieHTTPOnly: boolean;      // default True
    CSRFAcceptSecFetchSite: boolean;  // Validate Sec-Fetch-Site header
    RequireCSRFForMethods: TStringArray; // e.g. ['POST','PUT','PATCH','DELETE']
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
  private
    type
      TRateMap = specialize TStringHashMap<TTokenBucket>;
      TBruteMap = specialize TStringHashMap<TAttemptWindow>;
  public
    Cfg: TSecurityConfig;

    Lock: TCriticalSection;

    // Rate limit: key -> bucket
    Rate: TRateMap;

    // Brute: key -> attempt window
    Brute: TBruteMap;

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

    // CSRF Helpers (New/Updated)
    function ConstantTimeEquals(const A, B: string): boolean;
    function ValidateSecFetchSite(const R: TRequest): boolean;
    function CheckOriginReferer(const R: TRequest): boolean;
    function GetHostLower(const R: TRequest): string;
    function GetHeaderLower(const R: TRequest; const Name: string): string;
    class function NewRandomTokenHex(LenBytes: integer): string;

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

  Result.EnableCSRF := False; // Disabled by default unless configured
  Result.CSRFHeaderName := 'X-CSRF-Token';
  Result.CSRFCookieName := 'csrf_token';
  Result.CSRFTokenLength := 32;
  Result.CSRFSameSite := TResponseWriter.TCookieSameSite.ssLax;
  Result.CSRFSecureCookie := True;
  Result.CSRFTrustedOrigins := nil; // No trusted origins by default
  Result.CSRFCookieHTTPOnly := True; // HttpOnly by default
  Result.CSRFAcceptSecFetchSite := True; // Check Sec-Fetch-Site by default
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

  Rate := TRateMap.Create;
  Brute := TBruteMap.Create;
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

// Constant-time comparison to prevent timing attacks
function TSecurityState.ConstantTimeEquals(const A, B: string): boolean;
var
  I: integer;
  Diff: byte;
  LA, LB: integer;
begin
  LA := Length(A);
  LB := Length(B);

  // Length check is not constant time, but essential for logic
  if LA <> LB then Exit(False);

  Diff := 0;
  for I := 1 to LA do
    Diff := Diff or (byte(A[I]) xor byte(B[I]));
  Result := Diff = 0;
end;

class function TSecurityState.NewRandomTokenHex(LenBytes: integer): string;
var
  Buf: TBytes;
  I: Integer;
  B: Byte;
{$IFDEF MSWINDOWS}
  HProv: HCRYPTPROV;
{$ENDIF}
{$IFDEF UNIX}
  FD: cint;
  R: ssize_t;
{$ENDIF}
begin
  Result := '';
  if LenBytes <= 0 then Exit;

  SetLength(Buf, LenBytes);

  {$IFDEF MSWINDOWS}
  // Use Windows CSPRNG via CryptoAPI
  HProv := 0;
  if not CryptAcquireContext(HProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;
  try
    if not CryptGenRandom(HProv, DWORD(LenBytes), @Buf[0]) then
      RaiseLastOSError;
  finally
    CryptReleaseContext(HProv, 0);
  end;
  {$ELSEIF defined(UNIX)}
  // Use OS CSPRNG via /dev/urandom
  FD := fpOpen('/dev/urandom', O_RDONLY);
  if FD < 0 then
    raise Exception.Create('Cannot open /dev/urandom');
  try
    R := fpRead(FD, Buf[0], LenBytes);
    if R <> LenBytes then
      raise Exception.Create('Short read from /dev/urandom');
  finally
    fpClose(FD);
  end;
  {$ELSE}
  raise Exception.Create('No secure RNG implementation for this platform');
  {$ENDIF}

  SetLength(Result, LenBytes * 2);
  for I := 0 to LenBytes - 1 do
  begin
    B := Buf[I];
    Result[(I * 2) + 1] := IntToHex(B, 2)[1];
    Result[(I * 2) + 2] := IntToHex(B, 2)[2];
  end;
end;

// Validates Sec-Fetch-Site header if present (Fiber-style logic)
function TSecurityState.ValidateSecFetchSite(const R: TRequest): boolean;
var
  SFS: string;
begin
  if not Cfg.CSRFAcceptSecFetchSite then Exit(True);

  SFS := GetHeaderLower(R, 'Sec-Fetch-Site');

  // If header missing, pass (fallback to Origin check)
  if SFS = '' then Exit(True);

  // Allowed values: same-origin, same-site, none
  if (SFS = 'same-origin') or (SFS = 'same-site') or (SFS = 'none') then
    Exit(True);

  // 'cross-site' or unknown values -> Reject
  Exit(False);
end;

// Helper to parse origin URL and check trust
function TSecurityState.CheckOriginReferer(const R: TRequest): boolean;

  // Minimal URL parser for Origin/Referer (scheme://host[:port])
  procedure ParseURLHost(const U: string; out Scheme, Host: string);
  var
    P, Start: SizeInt;
    Tmp: string;
  begin
    Scheme := '';
    Host := '';
    Tmp := Trim(U);
    if Tmp = '' then Exit;

    // Scheme
    P := Pos('://', Tmp);
    if P > 0 then
    begin
      Scheme := LowerCase(Copy(Tmp, 1, P-1));
      Start := P + 3;
    end
    else
    begin
      Scheme := 'http'; // Default assumption? Or fail? Origin usually has scheme.
      Start := 1;
    end;

    // 2. Host (and port)
    Tmp := Copy(Tmp, Start, MaxInt);
    // Strip path
    P := Pos('/', Tmp);
    if P > 0 then Tmp := Copy(Tmp, 1, P-1);

    // Handle IPv6 [::1]
    if (Length(Tmp) > 0) and (Tmp[1] = '[') then
    begin
      P := Pos(']', Tmp);
      if P > 0 then Host := Copy(Tmp, 2, P-2);
      // Ignore port inside brackets for simplicity here
    end
    else
    begin
      // Strip port
      P := LastDelimiter(':', Tmp);
      // Check if colon is part of IPv6 (already handled) or port separator
      // Since we stripped brackets, a colon here is port.
      if P > 0 then
        Host := Copy(Tmp, 1, P-1)
      else
        Host := Tmp;
    end;

    Host := LowerCase(Host);
  end;

  function MatchWildcard(const Pattern, Value: string): boolean;
  begin
    // Pattern: *.example.com
    if (Length(Pattern) > 1) and (Pattern[1] = '*') and (Pattern[2] = '.') then
    begin
      // Check if Value ends with suffix (e.g., .example.com)
      // or Value equals suffix without dot (unlikely for domain, but still)
      // We check strict suffix matching: value = "sub.example.com", pattern = "*.example.com" -> suffix ".example.com"
      Exit( (Length(Value) >= Length(Pattern)-1) and
            (Copy(Value, Length(Value) - Length(Pattern) + 2, MaxInt) = Copy(Pattern, 2, MaxInt)) );
    end;
    Result := (Pattern = Value);
  end;

var
  Host, Origin, Referer: string;
  OriginScheme, OriginHost: string;
  RefererScheme, RefererHost: string;
  I: integer;
  TrustedPattern: string;
  TmpScheme, TmpHost: string;
begin
  Host := GetHostLower(R);
  if Host = '' then Exit(False); // Should not happen

  // Check Origin Header
  Origin := R.Header.GetValue('Origin');

  // Handle "null" origin (file://, data://, sandbox)
  if LowerCase(Trim(Origin)) = 'null' then
  begin
    // Treat as missing
    Origin := '';
  end;

  if Origin <> '' then
  begin
    ParseURLHost(Origin, OriginScheme, OriginHost);

    // Check strict match with Host
    if OriginHost = Host then Exit(True);

    // Check Trusted Origins
    for I := 0 to High(Cfg.CSRFTrustedOrigins) do
    begin
      TrustedPattern := Trim(Cfg.CSRFTrustedOrigins[I]);
      if TrustedPattern = '' then Continue;

      ParseURLHost(TrustedPattern, TmpScheme, TmpHost);

      // Must match scheme
      if (TmpScheme <> '') and (TmpScheme <> OriginScheme) then Continue;

      // Match host (wildcard supported)
      if MatchWildcard(TmpHost, OriginHost) then Exit(True);
    end;

    // Origin present but not trusted
    Exit(False);
  end;

  // Check Referer Header (Fallback)
  // "If Origin is missing: if TLS, require Referer; if not TLS, allow (Fiber logic)"
  if R.TLS then
  begin
    Referer := R.Header.GetValue('Referer');
    if Referer = '' then Exit(False);

    ParseURLHost(Referer, RefererScheme, RefererHost);

    // Must match Host
    if RefererHost = Host then Exit(True);

    // Check Trusted Origins
    for I := 0 to High(Cfg.CSRFTrustedOrigins) do
    begin
      TrustedPattern := Trim(Cfg.CSRFTrustedOrigins[I]);
      if TrustedPattern = '' then Continue;

      ParseURLHost(TrustedPattern, TmpScheme, TmpHost);
      if (TmpScheme <> '') and (TmpScheme <> RefererScheme) then Continue;

      if MatchWildcard(TmpHost, RefererHost) then Exit(True);
    end;

    Exit(False);
  end;

  // Not TLS and no Origin -> Allow (Fiber logic for legacy support)
  Result := True;
end;

procedure TSecurityState.EnsureCSRFCookie(W: TResponseWriter; R: TRequest);
var
  Tok: string;
  Secure: boolean;
  HttpOnly: boolean;
begin
  if not Cfg.EnableCSRF then Exit;
  if Cfg.CSRFCookieName = '' then Exit;

  Tok := R.CookieValue(Cfg.CSRFCookieName);
  if Tok = '' then
  begin
    Tok := NewRandomTokenHex(Cfg.CSRFTokenLength);

    // Determine Secure flag
    Secure := Cfg.CSRFSecureCookie and R.TLS;

    // SameSite=None requires Secure
    if (Cfg.CSRFSameSite = TResponseWriter.TCookieSameSite.ssNone) and (not Secure) then
      Secure := True; // Force Secure, though it won't work over HTTP in browsers

    // Determine HttpOnly flag
    HttpOnly := Cfg.CSRFCookieHTTPOnly;

    // Note: If HttpOnly=True, JS cannot read the token for double-submit.
    // For double-submit pattern, usually HttpOnly=False or token is provided via API/Body.
    // User must configure this correctly.

    W.SetCookie(Cfg.CSRFCookieName, Tok, '/', '', 0, -1, Secure, HttpOnly, Cfg.CSRFSameSite);
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
    // Ensure cookie exists for safe methods (GET) so client has it for later
    EnsureCSRFCookie(W, R);
    Exit(True);
  end;

  // Sec-Fetch-Site check (Modern browsers)
  if not ValidateSecFetchSite(R) then
  begin
    WriteError(W, 403, 'CSRF check failed (Sec-Fetch-Site)');
    Exit(False);
  end;

  // Origin/Referer Check
  if Cfg.EnforceOriginForUnsafe then
  begin
    if not CheckOriginReferer(R) then
    begin
      WriteError(W, 403, 'CSRF check failed (Origin/Referer)');
      Exit(False);
    end;
  end;

  // Double-Submit Cookie Check
  CookieTok := R.CookieValue(Cfg.CSRFCookieName);
  HeaderTok := R.Header.GetValue(Cfg.CSRFHeaderName);

  // Use Constant-time comparison
  if (CookieTok = '') or (HeaderTok = '') or (not ConstantTimeEquals(CookieTok, HeaderTok)) then
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
  Q, F: TStringList;
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

    Q := nil;
    F := nil;
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
  B: TTokenBucket;
  vNowMs: int64;
  Elapsed: double;
begin
  Result := True;
  if not Cfg.EnableRateLimit then Exit(True);
  if (Cfg.RateLimitRPS <= 0) or (Cfg.RateLimitBurst <= 0) then Exit(True);

  Key := ClientKey(R);
  vNowMs := NowMS;

  Lock.Enter;
  try
    if not Rate.Get(Key, B) then
    begin
      B.Tokens := Cfg.RateLimitBurst;
      B.LastTS := vNowMs;
      Rate.Insert(Key, B);
      Exit(True);
    end;

    Elapsed := (vNowMs - B.LastTS) / 1000.0;
    if Elapsed < 0 then Elapsed := 0;

    B.Tokens := Min(Cfg.RateLimitBurst, B.Tokens + Elapsed * Cfg.RateLimitRPS);
    B.LastTS := vNowMs;

    if B.Tokens < 1.0 then
    begin
      Rate.Insert(Key, B); // overwrite
      // Optional: Retry-After
      if not W.HeadersSent then
        W.Header.SetValue('Retry-After', '1');
      WriteError(W, 429, 'Too Many Requests');
      Exit(False);
    end;

    B.Tokens := B.Tokens - 1.0;
    Rate.Insert(Key, B); // overwrite
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

  // Best-effort JSON extraction
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
  A: TAttemptWindow;
  vNowMs: int64;
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
    if not Brute.Get(Key, A) then
    begin
      FillChar(A, SizeOf(A), 0);
      A.Count := 0;
      A.WindowStartMS := vNowMs;
      A.BlockUntilMS := 0;
      Brute.Insert(Key, A);
      Exit(True);
    end;

    if (A.BlockUntilMS > 0) and (vNowMs < A.BlockUntilMS) then
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
      A.WindowStartMS := vNowMs;
      A.BlockUntilMS := 0;
    end;

    Brute.Insert(Key, A); // overwrite refreshed state
  finally
    Lock.Leave;
  end;
end;

procedure TSecurityState.ObserveBruteForceResult(R: TRequest; StatusCode: integer);
var
  Key, IP, Ident: string;
  A: TAttemptWindow;
  vNowMs: int64;
begin
  if not Cfg.EnableBruteForce then Exit;
  if not IsLoginPath(R.Path) then Exit;
  if not SameText(R.Method, 'POST') then Exit;

  // Count only failures (401/403)
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
    if not Brute.Get(Key, A) then
    begin
      FillChar(A, SizeOf(A), 0);
      A.Count := 0;
      A.WindowStartMS := vNowMs;
      A.BlockUntilMS := 0;
    end;

    // Window reset
    if (Cfg.BruteWindowSeconds > 0) and (vNowMs - A.WindowStartMS > int64(Cfg.BruteWindowSeconds) * 1000) then
    begin
      A.Count := 0;
      A.WindowStartMS := vNowMs;
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

    Brute.Insert(Key, A); // overwrite
  finally
    Lock.Leave;
  end;
end;

function AdvancedSecurityMiddleware(const Cfg: TSecurityConfig): TMiddleware;
var
  State: TSecurityState;
begin
  // Randomize removed - using OS CSPRNG
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
  // Randomize removed
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

    // Rate limit first (cheap)
    if not State.CheckRateLimit(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    // Input checks
    if not State.CheckInputBasics(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    // Brute-force gate (pre)
    if not State.CheckBruteForcePre(Ctx.W, Ctx.R) then
    begin
      Ctx.Abort;
      Exit;
    end;

    // CSRF (unsafe methods)
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
