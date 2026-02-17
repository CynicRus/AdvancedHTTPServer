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

    // Extra / modern
    AllowPrivateNetwork: boolean;     // If true: handle PNA preflight and emit Access-Control-Allow-Private-Network
    AllowNullOrigin: boolean;         // If true: treat Origin: null as eligible for allow
    AllowedMethods: string;           // Static allow methods (comma-separated). Used if AutoMethodsFromRouter=false or router can't provide.
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
    Port: string;        // for wildcard port: '*' or '3000' etc
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

  Result.AllowPrivateNetwork := False;
  Result.AllowNullOrigin := False;
  Result.AllowedMethods := '';
end;

function TrimLower(const S: string): string; inline;
begin
  Result := LowerCase(Trim(S));
end;

function TryParsePortStrict(const S: string; out PortNum: integer): boolean;
var
  I: integer;
  V: int64;
begin
  Result := False;
  PortNum := -1;
  if S = '' then Exit(False);
  for I := 1 to Length(S) do
    if not (S[I] in ['0'..'9']) then Exit(False);

  V := StrToInt64Def(S, -1);
  if (V < 0) or (V > 65535) then Exit(False);
  PortNum := integer(V);
  Result := True;
end;

function NormalizeOriginLower_Request(const OriginRaw: string; out Scheme, Host, Port, Normalized: string): boolean;
var
  S: string;
  P, HStart, HEnd: SizeInt;
  PortNum: integer;
begin
  Result := False;
  Scheme := ''; Host := ''; Port := ''; Normalized := '';

  S := Trim(OriginRaw);
  if S = '' then Exit(False);

  if SameText(S, 'null') then
  begin
    // request parser recognizes it, policy will decide
    Normalized := 'null';
    Result := True;
    Exit;
  end;

  P := Pos('://', S);
  if P <= 0 then Exit(False);

  Scheme := LowerCase(Copy(S, 1, P - 1));
  if Scheme = '' then Exit(False);

  HStart := P + 3;
  if HStart > Length(S) then Exit(False);

  // Origin must be just scheme://host[:port] with no path/query/fragment
  if (Pos('/', Copy(S, HStart, MaxInt)) > 0) or
     (Pos('?', Copy(S, HStart, MaxInt)) > 0) or
     (Pos('#', Copy(S, HStart, MaxInt)) > 0) then
    Exit(False);

  // bracketed IPv6
  if (S[HStart] = '[') then
  begin
    HEnd := Pos(']', S);
    if HEnd <= 0 then Exit(False);
    Host := LowerCase(Copy(S, HStart, HEnd - HStart + 1));
    if (HEnd < Length(S)) and (S[HEnd + 1] = ':') then
    begin
      Port := Copy(S, HEnd + 2, MaxInt);
      if not TryParsePortStrict(Port, PortNum) then Exit(False);
      Port := IntToStr(PortNum);
    end;
  end
  else
  begin
    HEnd := LastDelimiter(':', S);
    if (HEnd > 0) and (HEnd >= HStart) then
    begin
      Host := LowerCase(Copy(S, HStart, HEnd - HStart));
      Port := Copy(S, HEnd + 1, MaxInt);
      if Host = '' then Exit(False);
      if not TryParsePortStrict(Port, PortNum) then Exit(False);
      Port := IntToStr(PortNum);
    end
    else
    begin
      Host := LowerCase(Copy(S, HStart, MaxInt));
      if Host = '' then Exit(False);
    end;
  end;

  if Port <> '' then
    Normalized := Scheme + '://' + Host + ':' + Port
  else
    Normalized := Scheme + '://' + Host;

  Result := True;
end;

function NormalizeOriginLower_Pattern(const PatternRaw: string; out Scheme, Host, Port, Normalized: string): boolean;
var
  S: string;
  P, HStart, HEnd: SizeInt;
  PortNumCheck: integer;
begin
  Result := False;
  Scheme := ''; Host := ''; Port := ''; Normalized := '';

  S := Trim(PatternRaw);
  if S = '' then Exit(False);

  if SameText(S, 'null') then
  begin
    Normalized := 'null';
    Result := True;
    Exit;
  end;

  P := Pos('://', S);
  if P <= 0 then Exit(False);

  Scheme := LowerCase(Copy(S, 1, P - 1));
  if Scheme = '' then Exit(False);

  HStart := P + 3;
  if HStart > Length(S) then Exit(False);

  // Patterns also must not include path/query/fragment
  if (Pos('/', Copy(S, HStart, MaxInt)) > 0) or
     (Pos('?', Copy(S, HStart, MaxInt)) > 0) or
     (Pos('#', Copy(S, HStart, MaxInt)) > 0) then
    Exit(False);

  // bracketed IPv6, port cannot be '*'
  if (S[HStart] = '[') then
  begin
    HEnd := Pos(']', S);
    if HEnd <= 0 then Exit(False);
    Host := LowerCase(Copy(S, HStart, HEnd - HStart + 1));
    if (HEnd < Length(S)) and (S[HEnd + 1] = ':') then
      Port := Copy(S, HEnd + 2, MaxInt)
    else
      Port := '';
    if Port = '*' then Exit(False);
  end
  else
  begin
    HEnd := LastDelimiter(':', S);
    if (HEnd > 0) and (HEnd >= HStart) then
    begin
      Host := LowerCase(Copy(S, HStart, HEnd - HStart));
      Port := Copy(S, HEnd + 1, MaxInt);
      if Host = '' then Exit(False);
      // For patterns allow numeric port or '*'
      if (Port <> '') and (Port <> '*') then
        if not TryParsePortStrict(Port, PortNumCheck) then Exit(False);
    end
    else
    begin
      Host := LowerCase(Copy(S, HStart, MaxInt));
      if Host = '' then Exit(False);
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
  // Use Pattern normalization
  if not NormalizeOriginLower_Pattern(P, Scheme, Host, Port, Norm) then
    Exit(False);

  // Exact by default
  Rule.Kind := orkExact;
  Rule.Exact := Norm;
  Result := True;

  // wildcard host forms:
  // scheme://*.example.com[:port?]
  // scheme://*.example.com:*  (any port)
  // scheme://host:*           (any port)

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

  if not NormalizeOriginLower_Request(OriginRaw, Scheme, Host, Port, NormalizedOrigin) then
    Exit(False);

  // Origin: null policy gate
  if NormalizedOrigin = 'null' then
  begin
    if not Cfg.AllowNullOrigin then
      Exit(False);

    // AllowAnyOrigin => allow (will be reflected as "null" if AllowCredentials or AllowAnyOrigin=false logic reflects)
    if Cfg.AllowAnyOrigin then
      Exit(True);

    // Otherwise only if explicitly present in rules (exact 'null') or orkAny
    for I := 0 to High(Rules) do
      if (Rules[I].Kind = orkAny) or ((Rules[I].Kind = orkExact) and (Rules[I].Exact = 'null')) then
        Exit(True);

    Exit(False);
  end;

  if Cfg.AllowAnyOrigin then
    Exit(True);

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
      // Cache poisoning protection for preflight reflection
      AppendVaryHeader(Ctx.W.Header, 'Access-Control-Request-Method');

      // Private Network Access (PNA)
      if State.Cfg.AllowPrivateNetwork and
         SameText(Trim(Ctx.R.Header.GetValue('Access-Control-Request-Private-Network')), 'true') then
      begin
        AppendVaryHeader(Ctx.W.Header, 'Access-Control-Request-Private-Network');
        Ctx.W.Header.SetValue('Access-Control-Allow-Private-Network', 'true');
      end;

      // Methods logic
      AllowMethods := '';

      // Prefer router-derived "Allow" if enabled
      if State.Cfg.AutoMethodsFromRouter and (State.Router <> nil) then
      begin
        PathNorm := State.Router.NormalizePath(Ctx.R.Path);
        AllowMethods := State.ResolveAllowMethodsForPath(PathNorm);
      end;

      //  If router didn't provide, use static config string if present
      if Trim(AllowMethods) = '' then
        AllowMethods := Trim(State.Cfg.AllowedMethods);

      //  Final fallback: reflect Access-Control-Request-Method
      if Trim(AllowMethods) = '' then
      begin
        AllowMethods := Trim(Ctx.R.Header.GetValue('Access-Control-Request-Method'));
      end;

      if Trim(AllowMethods) <> '' then
        Ctx.W.Header.SetValue('Access-Control-Allow-Methods', AllowMethods);

      // Headers
      if Trim(State.Cfg.AllowedHeaders) <> '' then
        Ctx.W.Header.SetValue('Access-Control-Allow-Headers', Trim(State.Cfg.AllowedHeaders))
      else
      begin
        ReqHeaders := Trim(Ctx.R.Header.GetValue('Access-Control-Request-Headers'));
        if ReqHeaders <> '' then
        begin
          //  vary by ACRH when reflecting
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
