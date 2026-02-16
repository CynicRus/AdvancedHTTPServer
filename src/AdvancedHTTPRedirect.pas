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

unit AdvancedHTTPRedirect;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, StrUtils,
  AdvancedHTTPServer, AdvancedHTTPRouter;

type
  TRedirectLogic = reference to function(const Scheme, Host, URI: string; out URL: string): boolean;

  TRedirectConfig = record
    Enabled: boolean;

    // HTTP status (301/302/307/308). Default: 301
    Code: integer;

    // Skip conditions
    SkipMethods: TStringArray;   // default: ['OPTIONS']
    SkipPaths: TStringArray;     // exact match
    SkipPrefix: TStringArray;    // prefix match


    // If true: try to detect original scheme from proxy headers.
    // Uses X-Forwarded-Proto first, then Forwarded: proto=...
    RespectProxyHeaders: boolean;
    // If empty, default logic chosen by helper constructor.
    Redirect: TRedirectLogic;
  end;

function RedirectDefaultConfig: TRedirectConfig;

// Router middleware: router.Use(...)
function RedirectRouterMiddleware(const Cfg: TRedirectConfig): TRouterMiddleware;

// Helpers to build configs like Echo
function RedirectHTTPSConfig: TRedirectConfig;
function RedirectHTTPSWWWConfig: TRedirectConfig;
function RedirectHTTPSNonWWWConfig: TRedirectConfig;
function RedirectWWWConfig: TRedirectConfig;
function RedirectNonWWWConfig: TRedirectConfig;

implementation

const
  WWW_PREFIX = 'www.';

function RedirectDefaultConfig: TRedirectConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Enabled := True;
  Result.Code := 301;
  Result.SkipMethods := ['OPTIONS'];
  Result.SkipPaths := nil;
  Result.SkipPrefix := nil;
  Result.RespectProxyHeaders := True;
  Result.Redirect := nil;
end;

function SameTextInArray(const S: string; const A: TStringArray): boolean;
var
  I: integer;
begin
  for I := 0 to High(A) do
    if SameText(S, A[I]) then Exit(True);
  Result := False;
end;

function StartsWithText(const S, Prefix: string): boolean; inline;
begin
  if Prefix = '' then Exit(True);
  if Length(S) < Length(Prefix) then Exit(False);
  Result := Copy(S, 1, Length(Prefix)) = Prefix;
end;

function ShouldSkip(const R: TRequest; const Cfg: TRedirectConfig): boolean;
var
  I: integer;
begin
  if not Cfg.Enabled then Exit(True);

  if SameTextInArray(R.Method, Cfg.SkipMethods) then Exit(True);

  for I := 0 to High(Cfg.SkipPaths) do
    if SameText(R.Path, Cfg.SkipPaths[I]) then Exit(True);

  for I := 0 to High(Cfg.SkipPrefix) do
    if (Cfg.SkipPrefix[I] <> '') and StartsWithText(R.Path, Cfg.SkipPrefix[I]) then
      Exit(True);

  Result := False;
end;

function ExtractForwardedProtoLower(const Forwarded: string): string;
var
  S, Part, Item: string;
  CommaPos, SemiPos, EqPos: SizeInt;
begin
  // Forwarded: for=...;proto=https;host=...
  Result := '';
  S := Trim(Forwarded);
  if S = '' then Exit('');

  // only first element before comma
  CommaPos := Pos(',', S);
  if CommaPos > 0 then
    S := Copy(S, 1, CommaPos - 1);

  // scan semi-separated key=val
  while S <> '' do
  begin
    SemiPos := Pos(';', S);
    if SemiPos > 0 then
    begin
      Part := Trim(Copy(S, 1, SemiPos - 1));
      S := Trim(Copy(S, SemiPos + 1, MaxInt));
    end
    else
    begin
      Part := Trim(S);
      S := '';
    end;

    if Part = '' then Continue;

    EqPos := Pos('=', Part);
    if EqPos <= 0 then Continue;

    Item := LowerCase(Trim(Copy(Part, 1, EqPos - 1)));
    if Item <> 'proto' then Continue;

    Result := LowerCase(Trim(Copy(Part, EqPos + 1, MaxInt)));
    // strip quotes
    if (Length(Result) >= 2) and (Result[1] = '"') and (Result[Length(Result)] = '"') then
      Result := Copy(Result, 2, Length(Result) - 2);
    Exit(Result);
  end;
end;

function DetectScheme(const R: TRequest; const Cfg: TRedirectConfig): string;
var
  XFP, Fwd: string;
begin
  // baseline: TLS flag
  if R.TLS then Result := 'https' else Result := 'http';

  if not Cfg.RespectProxyHeaders then Exit;

  XFP := LowerCase(Trim(R.Header.GetValue('X-Forwarded-Proto')));
  if XFP <> '' then
  begin
    // may be "https, http" — take first
    if Pos(',', XFP) > 0 then
      XFP := Trim(Copy(XFP, 1, Pos(',', XFP) - 1));
    if (XFP = 'http') or (XFP = 'https') then
      Exit(XFP);
  end;

  Fwd := ExtractForwardedProtoLower(R.Header.GetValue('Forwarded'));
  if (Fwd = 'http') or (Fwd = 'https') then
    Exit(Fwd);
end;

function HostHasWWW(const HostLower: string): boolean; inline;
begin
  Result := (Length(HostLower) >= Length(WWW_PREFIX)) and (LeftStr(HostLower, Length(WWW_PREFIX)) = WWW_PREFIX);
end;

function SplitHostPort(const Host: string; out HostOnly, Port: string): boolean;
var
  H: string;
  P: SizeInt;
begin
  // Host header can be:
  // - example.com
  // - example.com:8080
  // - [::1]
  // - [::1]:8080
  HostOnly := '';
  Port := '';
  H := Trim(Host);
  if H = '' then Exit(False);

  if (H[1] = '[') then
  begin
    P := Pos(']', H);
    if P <= 0 then Exit(False);
    HostOnly := Copy(H, 1, P); // keep brackets
    if (P < Length(H)) and (H[P+1] = ':') then
      Port := Copy(H, P+2, MaxInt);
    Exit(True);
  end;

  P := LastDelimiter(':', H);
  if (P > 0) and (Pos(':', Copy(H, 1, P-1)) = 0) then
  begin
    HostOnly := Copy(H, 1, P-1);
    Port := Copy(H, P+1, MaxInt);
  end
  else
    HostOnly := H;

  Result := HostOnly <> '';
end;

function JoinHostPort(const HostOnly, Port: string): string;
begin
  if Port <> '' then
    Result := HostOnly + ':' + Port
  else
    Result := HostOnly;
end;

function RequestURI(const R: TRequest): string;
begin
  // we have Path + RawQuery
  if R.RawQuery <> '' then
    Result := R.Path + '?' + R.RawQuery
  else
    Result := R.Path;
end;

function RedirectHTTPSLogic(const Scheme, Host, URI: string; out URL: string): boolean;
begin
  if LowerCase(Scheme) <> 'https' then
  begin
    URL := 'https://' + Host + URI;
    Exit(True);
  end;
  URL := '';
  Result := False;
end;

function RedirectWWWLogic(const Scheme, Host, URI: string; out URL: string): boolean;
var
  HostOnly, Port, HL: string;
begin
  if not SplitHostPort(Host, HostOnly, Port) then Exit(False);
  HL := LowerCase(HostOnly);
  if not HostHasWWW(HL) then
  begin
    URL := Scheme + '://' + JoinHostPort(WWW_PREFIX + HostOnly, Port) + URI;
    Exit(True);
  end;
  URL := '';
  Result := False;
end;

function RedirectNonWWWLogic(const Scheme, Host, URI: string; out URL: string): boolean;
var
  HostOnly, Port, HL: string;
begin
  if not SplitHostPort(Host, HostOnly, Port) then Exit(False);
  HL := LowerCase(HostOnly);
  if HostHasWWW(HL) then
  begin
    URL := Scheme + '://' + JoinHostPort(Copy(HostOnly, Length(WWW_PREFIX)+1, MaxInt), Port) + URI;
    Exit(True);
  end;
  URL := '';
  Result := False;
end;

function RedirectHTTPSWWWLogic(const Scheme, Host, URI: string; out URL: string): boolean;
var
  HostOnly, Port, HL, HNoW: string;
begin
  if not SplitHostPort(Host, HostOnly, Port) then Exit(False);
  HL := LowerCase(HostOnly);

  // if not https OR missing www => redirect
  if (LowerCase(Scheme) <> 'https') or (not HostHasWWW(HL)) then
  begin
    HNoW := HostOnly;
    if HostHasWWW(HL) then
      HNoW := Copy(HostOnly, Length(WWW_PREFIX)+1, MaxInt);
    URL := 'https://' + JoinHostPort(WWW_PREFIX + HNoW, Port) + URI;
    Exit(True);
  end;

  URL := '';
  Result := False;
end;

function RedirectHTTPSNonWWWLogic(const Scheme, Host, URI: string; out URL: string): boolean;
var
  HostOnly, Port, HL, HNoW: string;
begin
  if not SplitHostPort(Host, HostOnly, Port) then Exit(False);
  HL := LowerCase(HostOnly);

  // if not https OR has www => redirect
  if (LowerCase(Scheme) <> 'https') or HostHasWWW(HL) then
  begin
    HNoW := HostOnly;
    if HostHasWWW(HL) then
      HNoW := Copy(HostOnly, Length(WWW_PREFIX)+1, MaxInt);
    URL := 'https://' + JoinHostPort(HNoW, Port) + URI;
    Exit(True);
  end;

  URL := '';
  Result := False;
end;

function RedirectRouterMiddleware(const Cfg: TRedirectConfig): TRouterMiddleware;
var
  CC: TRedirectConfig;
begin
  CC := Cfg;
  if CC.Code = 0 then CC.Code := 301;

  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    Scheme, Host, URI, URL: string;
  begin
    Ctx := THTTPRouterContext(C);

    if ShouldSkip(Ctx.R, CC) then
    begin
      Ctx.Next;
      Exit;
    end;

    if not Assigned(CC.Redirect) then
    begin
      Ctx.Next;
      Exit;
    end;

    Host := Trim(Ctx.R.Header.GetValue('Host'));
    if Host = '' then
    begin
      Ctx.Next;
      Exit;
    end;

    Scheme := DetectScheme(Ctx.R, CC);
    URI := RequestURI(Ctx.R);

    if CC.Redirect(Scheme, Host, URI, URL) then
    begin
      if not Ctx.W.HeadersSent then
      begin
        Ctx.W.Header.SetValue('Location', URL);
        Ctx.W.WriteHeader(CC.Code);

        // no autoredirect client case
        if (UpperCase(Ctx.R.Method) <> 'HEAD') then
          Ctx.W.Write('Redirecting to ' + URL);
      end;
      Ctx.Abort;
      Exit;
    end;

    Ctx.Next;
  end;
end;

function RedirectHTTPSConfig: TRedirectConfig;
begin
  Result := RedirectDefaultConfig;
  Result.Redirect := @RedirectHTTPSLogic;
end;

function RedirectHTTPSWWWConfig: TRedirectConfig;
begin
  Result := RedirectDefaultConfig;
  Result.Redirect := @RedirectHTTPSWWWLogic;
end;

function RedirectHTTPSNonWWWConfig: TRedirectConfig;
begin
  Result := RedirectDefaultConfig;
  Result.Redirect := @RedirectHTTPSNonWWWLogic;
end;

function RedirectWWWConfig: TRedirectConfig;
begin
  Result := RedirectDefaultConfig;
  Result.Redirect := @RedirectWWWLogic;
end;

function RedirectNonWWWConfig: TRedirectConfig;
begin
  Result := RedirectDefaultConfig;
  Result.Redirect := @RedirectNonWWWLogic;
end;

end.
