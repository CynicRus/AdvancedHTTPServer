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

unit AdvancedHTTPCORS;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch anonymousfunctions}
{$modeswitch functionreferences}

interface

uses
  SysUtils, Classes, StrUtils,
  AdvancedHTTPRouter, AdvancedHTTPServer;

type
  TCorsConfig = record
    // Origins
    AllowAnyOrigin: boolean;          // True: allow any Origin (if AllowCredentials=true, Origin will be reflected)
    AllowedOrigins: TStringArray;     // exact + templates ('https://*.example.com', 'http://localhost:*', '*')

    // Headers
    AllowedHeaders: string;           // If empty: take from Access-Control-Request-Headers (for preflight)
    ExposedHeaders: string;           // Access-Control-Expose-Headers

    // Credentials & caching
    AllowCredentials: boolean;        // Access-Control-Allow-Credentials: true
    MaxAgeSeconds: integer;           // Access-Control-Max-Age

    // Behavior
    AbortPreflight: boolean;          // True: Respond to OPTIONS preflight directly in middleware
    AutoMethodsFromRouter: boolean;   // True: Access-Control-Allow-Methods build from routes (Allow header)
  end;

function CorsDefaultConfig: TCorsConfig;
function CorsMiddleware(const Router: THTTPRouter; const Cfg: TCorsConfig): TRouterMiddleware;

implementation

type
  TCorsOriginRuleKind = (orkAny, orkExact, orkWildcardHost, orkWildcardPort, orkWildcardHostAndPort);

  TCorsOriginRule = record
    Kind: TCorsOriginRuleKind;
    Exact: string;       // for orkExact: normalized lower origin 'scheme://host[:port]'
    Scheme: string;      // for wildcard kinds
    HostSuffix: string;  // for wildcard host: '.example.com' (без '*')
    Port: string;        // for wildcard port: '*' or '3000' etc (в наших вариантах '*' значит any)
  end;

  TCorsState = class
  public
    Router: THTTPRouter;
    Cfg: TCorsConfig;
    Rules: array of TCorsOriginRule;

    // cache: path -> allowMethods string (from router's Allow)
    MethodsCache: TStringList;

    constructor Create(ARouter: THTTPRouter; const ACfg: TCorsConfig);
    destructor Destroy; override;

    function IsOriginAllowed(const OriginRaw: string; out NormalizedOrigin: string): boolean;
    function ResolveAllowMethodsForPath(const Path: string): string;
  end;

function CorsDefaultConfig: TCorsConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.AllowAnyOrigin := True;
  Result.AllowedOrigins := nil;

  Result.AllowedHeaders := '';
  Result.ExposedHeaders := '';
  Result.AllowCredentials := False;
  Result.MaxAgeSeconds := 600;

  Result.AbortPreflight := True;
  Result.AutoMethodsFromRouter := True;
end;

function TrimLower(const S: string): string; inline;
begin
  Result := LowerCase(Trim(S));
end;

function NormalizeOriginLower(const OriginRaw: string; out Scheme, Host, Port, Normalized: string): boolean;
var
  S: string;
  P, HStart, HEnd: SizeInt;
begin
  Result := False;
  Scheme := ''; Host := ''; Port := ''; Normalized := '';

  S := Trim(OriginRaw);
  if S = '' then Exit(False);

  // We accept only scheme://...
  P := Pos('://', S);
  if P <= 0 then Exit(False);

  Scheme := LowerCase(Copy(S, 1, P - 1));
  if (Scheme = '') then Exit(False);

  // host[:port] (we ignore any path; per Origin header it must not have it)
  HStart := P + 3;
  if HStart > Length(S) then Exit(False);

  // strip trailing slash just in case
  if (Length(S) > HStart) and (S[Length(S)] = '/') then
    SetLength(S, Length(S) - 1);

  // bracketed IPv6: [::1]:3000
  if (HStart <= Length(S)) and (S[HStart] = '[') then
  begin
    HEnd := Pos(']', S);
    if HEnd <= 0 then Exit(False);
    Host := LowerCase(Copy(S, HStart, HEnd - HStart + 1)); // keep brackets
    if (HEnd < Length(S)) and (S[HEnd + 1] = ':') then
      Port := Copy(S, HEnd + 2, MaxInt)
    else
      Port := '';
  end
  else
  begin
    // host[:port]
    HEnd := LastDelimiter(':', S);
    if (HEnd > 0) and (HEnd >= HStart) and (Pos('://', Copy(S, HEnd, MaxInt)) = 0) then
    begin
      // if there is exactly one ':' after scheme and it looks like port separator
      Host := LowerCase(Copy(S, HStart, HEnd - HStart));
      Port := Copy(S, HEnd + 1, MaxInt);
      // If host becomes empty, treat as invalid
      if Host = '' then Exit(False);
      // If Port contains '/', invalid for Origin, but ignore by marking invalid:
      if Pos('/', Port) > 0 then Exit(False);
    end
    else
    begin
      Host := LowerCase(Copy(S, HStart, MaxInt));
      Port := '';
      if (Host = '') or (Pos('/', Host) > 0) then Exit(False);
    end;
  end;

  if Port <> '' then
    Normalized := Scheme + '://' + Host + ':' + Port
  else
    Normalized := Scheme + '://' + Host;

  Result := True;
end;

function ParseAllowedOriginRule(const PatternRaw: string; out Rule: TCorsOriginRule): boolean;
var
  P, Scheme, Host, Port, Norm: string;
  H: string;
begin
  Result := False;
  FillChar(Rule, SizeOf(Rule), 0);

  P := Trim(PatternRaw);
  if P = '' then Exit(False);

  if P = '*' then
  begin
    Rule.Kind := orkAny;
    Exit(True);
  end;

  // exact or wildcard forms only in scheme://...
  if not NormalizeOriginLower(P, Scheme, Host, Port, Norm) then
    Exit(False);

  // Exact by default
  Rule.Kind := orkExact;
  Rule.Exact := Norm;
  Result := True;

  // wildcard host forms:
  // scheme://*.example.com[:port?]
  // scheme://*.example.com:*  (any port)
  // scheme://host:*           (any port)
  // scheme://*.* ??? not supported

  // wildcard port
  if Port = '*' then
  begin
    // host may still have wildcard
    Rule.Scheme := Scheme;
    Rule.Port := '*';
    H := Host;

    if (Length(H) >= 2) and (LeftStr(H, 2) = '*.') then
    begin
      // suffix match on domain labels
      Rule.Kind := orkWildcardHostAndPort;
      Rule.HostSuffix := Copy(H, 2, MaxInt); // keep ".example.com"
      Exit(True);
    end
    else
    begin
      Rule.Kind := orkWildcardPort;
      Rule.HostSuffix := H; // store full host for exact-host + any port
      Exit(True);
    end;
  end;

  // wildcard host without wildcard port
  if (Length(Host) >= 2) and (LeftStr(Host, 2) = '*.') then
  begin
    Rule.Kind := orkWildcardHost;
    Rule.Scheme := Scheme;
    Rule.HostSuffix := Copy(Host, 2, MaxInt); // ".example.com"
    Rule.Port := Port; // '' or concrete
    Exit(True);
  end;

end;

function EndsWithTextCI(const S, Suffix: string): boolean; inline;
var
  LS, LSu: SizeInt;
begin
  LS := Length(S);
  LSu := Length(Suffix);
  if LSu = 0 then Exit(True);
  if LS < LSu then Exit(False);
  Result := Copy(S, LS - LSu + 1, LSu) = Suffix;
end;

function HostMatchesWildcardSuffix(const HostLower, SuffixWithDotLower: string): boolean; inline;
begin
  // Require at least one label before suffix: foo.example.com matches .example.com
  // but example.com does NOT match .example.com
  if not EndsWithTextCI(HostLower, SuffixWithDotLower) then Exit(False);
  Result := Length(HostLower) > Length(SuffixWithDotLower);
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

function IsPreflight(const R: TRequest): boolean; inline;
begin
  Result :=
    SameText(R.Method, 'OPTIONS') and
    (R.Header.GetValue('Origin') <> '') and
    (R.Header.GetValue('Access-Control-Request-Method') <> '');
end;

{ TCorsState }

constructor TCorsState.Create(ARouter: THTTPRouter; const ACfg: TCorsConfig);
var
  I, N: integer;
  R: TCorsOriginRule;
begin
  inherited Create;
  Router := ARouter;
  Cfg := ACfg;

  SetLength(Rules, 0);
  if (not Cfg.AllowAnyOrigin) and (Length(Cfg.AllowedOrigins) > 0) then
  begin
    N := 0;
    SetLength(Rules, Length(Cfg.AllowedOrigins));
    for I := 0 to High(Cfg.AllowedOrigins) do
      if ParseAllowedOriginRule(Cfg.AllowedOrigins[I], R) then
      begin
        Rules[N] := R;
        Inc(N);
      end;
    SetLength(Rules, N);
  end;

  MethodsCache := TStringList.Create;
  MethodsCache.CaseSensitive := False;
  MethodsCache.Sorted := True;
  MethodsCache.Duplicates := dupIgnore;
end;

destructor TCorsState.Destroy;
begin
  MethodsCache.Free;
  inherited Destroy;
end;

function TCorsState.IsOriginAllowed(const OriginRaw: string; out NormalizedOrigin: string): boolean;
var
  Scheme, Host, Port: string;
  I: integer;
  R: TCorsOriginRule;
begin
  NormalizedOrigin := '';
  if OriginRaw = '' then Exit(False);

  if Cfg.AllowAnyOrigin then
  begin
    // Still normalize for reflect / vary correctness and to reject garbage
    Result := NormalizeOriginLower(OriginRaw, Scheme, Host, Port, NormalizedOrigin);
    Exit(Result);
  end;

  if not NormalizeOriginLower(OriginRaw, Scheme, Host, Port, NormalizedOrigin) then
    Exit(False);

  for I := 0 to High(Rules) do
  begin
    R := Rules[I];
    case R.Kind of
      orkAny:
        Exit(True);

      orkExact:
        if NormalizedOrigin = R.Exact then
          Exit(True);

      orkWildcardHost:
        begin
          if Scheme <> R.Scheme then Continue;
          // port must match (empty means "no port in origin pattern")
          if (R.Port <> '') and (Port <> R.Port) then Continue;
          if HostMatchesWildcardSuffix(Host, R.HostSuffix) then
            Exit(True);
        end;

      orkWildcardPort:
        begin
          if Scheme <> R.Scheme then Continue;
          // exact host, any port (including empty)
          if Host = R.HostSuffix then
            Exit(True);
        end;

      orkWildcardHostAndPort:
        begin
          if Scheme <> R.Scheme then Continue;
          if HostMatchesWildcardSuffix(Host, R.HostSuffix) then
            Exit(True);
        end;
    end;
  end;

  Result := False;
end;

function TCorsState.ResolveAllowMethodsForPath(const Path: string): string;
var
  Key: string;
  Idx: integer;
  AllowHeader: string;
  HasAny: boolean;
begin
  Key := Path;
  // cache lookup
  Idx := MethodsCache.IndexOfName(Key);
  if Idx >= 0 then
    Exit(MethodsCache.ValueFromIndex[Idx]);

  AllowHeader := '';
  HasAny := False;

  // Router returns "Allow" header string (GET, POST, ... + OPTIONS)
  if (Router <> nil) and Router.IsOptionsAutoResponsePossible(Key, AllowHeader, HasAny) and HasAny then
    Result := AllowHeader
  else
    Result := ''; // unknown path (404 preflight) or no methods

  MethodsCache.Values[Key] := Result;
end;

function CorsMiddleware(const Router: THTTPRouter; const Cfg: TCorsConfig): TRouterMiddleware;
var
  State: TCorsState;
begin
  State := TCorsState.Create(Router, Cfg);

  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    OriginRaw, OriginNorm: string;
    AllowOriginValue: string;
    ReqHeaders: string;
    AllowMethods: string;
    PathNorm: string;
  begin
    Ctx := THTTPRouterContext(C);

    OriginRaw := Ctx.R.Header.GetValue('Origin');
    if OriginRaw = '' then
    begin
      Ctx.Next;
      Exit;
    end;

    if not State.IsOriginAllowed(OriginRaw, OriginNorm) then
    begin
      // Like most frameworks: we simply don't add CORS headers.
      Ctx.Next;
      Exit;
    end;

    // vary for caches when Origin participates
    AppendVaryHeader(Ctx.W.Header, 'Origin');

    // Access-Control-Allow-Origin
    if (not State.Cfg.AllowAnyOrigin) or State.Cfg.AllowCredentials then
      AllowOriginValue := OriginNorm // reflect normalized origin
    else
      AllowOriginValue := '*';

    Ctx.W.Header.SetValue('Access-Control-Allow-Origin', AllowOriginValue);

    if State.Cfg.AllowCredentials then
      Ctx.W.Header.SetValue('Access-Control-Allow-Credentials', 'true');

    if State.Cfg.ExposedHeaders <> '' then
      Ctx.W.Header.SetValue('Access-Control-Expose-Headers', Trim(State.Cfg.ExposedHeaders));

    // Preflight
    if State.Cfg.AbortPreflight and IsPreflight(Ctx.R) then
    begin
      // Methods: from router routes if enabled
      if State.Cfg.AutoMethodsFromRouter and (State.Router <> nil) then
      begin
        // normalize path same as router does to hit cache keys consistently
        PathNorm := State.Router.NormalizePath(Ctx.R.Path);
        AllowMethods := State.ResolveAllowMethodsForPath(PathNorm);
        if AllowMethods <> '' then
          Ctx.W.Header.SetValue('Access-Control-Allow-Methods', AllowMethods);
      end
      else
      begin
        // fallback (static list)
      end;

      // Headers
      if Trim(State.Cfg.AllowedHeaders) <> '' then
        Ctx.W.Header.SetValue('Access-Control-Allow-Headers', Trim(State.Cfg.AllowedHeaders))
      else
      begin
        ReqHeaders := Trim(Ctx.R.Header.GetValue('Access-Control-Request-Headers'));
        if ReqHeaders <> '' then
        begin
          // recommended: vary by ACRH when reflecting
          AppendVaryHeader(Ctx.W.Header, 'Access-Control-Request-Headers');
          Ctx.W.Header.SetValue('Access-Control-Allow-Headers', ReqHeaders);
        end;
      end;

      // Cache preflight
      if State.Cfg.MaxAgeSeconds > 0 then
        Ctx.W.Header.SetValue('Access-Control-Max-Age', IntToStr(State.Cfg.MaxAgeSeconds));

      // 204 No Content
      Ctx.W.WriteHeader(204);
      Ctx.Abort;
      Exit;
    end;

    Ctx.Next;
  end;
end;

initialization
  // nothing
finalization

end.

