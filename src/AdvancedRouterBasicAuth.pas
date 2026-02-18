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

unit AdvancedRouterBasicAuth;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, StrUtils,
  AdvancedHTTPRouter, AdvancedHTTPServer,
  base64, ctypes
  {$IF defined(UNIX) or defined(WINDOWS)}
  , patched_openssl
  {$IFEND}
  ;

type
  TBasicAuthAuthorizer = reference to function(const User, Pass: string; Ctx: THTTPRouterContext): boolean;

  TBasicAuthConfig = record
    Next: reference to function(Ctx: THTTPRouterContext): boolean; // skip middleware
    Users: TStringList; // Name=Password (plain OR hashed forms supported)
    Authorizer: TBasicAuthAuthorizer;

    Realm: string;
    Charset: string;       // '' or 'UTF-8'
    HeaderLimit: integer;  // e.g. 8192

    Unauthorized: reference to procedure(Ctx: THTTPRouterContext);
    BadRequest: reference to procedure(Ctx: THTTPRouterContext);
  end;

function BasicAuth(const Cfg: TBasicAuthConfig): TRouterMiddleware;
function DefaultBasicAuthConfig: TBasicAuthConfig;

implementation

const
  BASIC_SCHEME = 'Basic';

type
  TPassKind = (pkPlain, pkSHA256, pkSHA512, pkBcrypt);

  TParsedPass = record
    Kind: TPassKind;
    Digest: rawbytestring;   // for SHA256/SHA512: raw digest bytes
    BcryptHash: string;      // for bcrypt
    Plain: string;           // for pkPlain
    Valid: boolean;
  end;

function IsAsciiPrintableOrTab(const S: string): boolean;
var
  I: Integer;
  B: Byte;
begin
  for I := 1 to Length(S) do
  begin
    B := Ord(S[I]);
    if (B = $7F) then Exit(False);
    if (B < $20) and (B <> 9) then Exit(False);
    if (B >= $80) then Exit(False);
  end;
  Result := True;
end;

function ContainsCTL(const S: string): boolean;
var
  I: Integer;
  B: Byte;
begin
  for I := 1 to Length(S) do
  begin
    B := Ord(S[I]);
    if (B < $20) or (B = $7F) then Exit(True);
  end;
  Result := False;
end;

function TrimSpace(const S: string): string;
begin
  Result := SysUtils.Trim(S);
end;

function StartsWithCaseInsensitive(const S, Prefix: string): boolean;
begin
  Result := (Length(S) >= Length(Prefix)) and SameText(Copy(S, 1, Length(Prefix)), Prefix);
end;

function IndexOfAnySpace(const S: string): integer;
var
  I: Integer;
begin
  for I := 1 to Length(S) do
    if S[I] in [#9, #10, #11, #12, #13, ' '] then
      Exit(I);
  Result := 0;
end;

function Base64DecodeStdOrRaw(const Inp: string; out OutStr: rawbytestring): boolean;
var
  S: string;
  PadNeed: Integer;
begin
  Result := False;
  OutStr := '';

  try
    OutStr := DecodeStringBase64(Inp);
    Exit(True);
  except
  end;

  try
    S := Inp;
    PadNeed := (4 - (Length(S) mod 4)) mod 4;
    if PadNeed > 0 then
      S := S + StringOfChar('=', PadNeed);
    OutStr := DecodeStringBase64(S);
    Result := True;
  except
    Result := False;
  end;
end;

procedure DefaultUnauthorized(const Cfg: TBasicAuthConfig; Ctx: THTTPRouterContext);
var
  H: string;
begin
  H := 'Basic realm="' + StringReplace(Cfg.Realm, '"', '\"', [rfReplaceAll]) + '"';
  if Cfg.Charset <> '' then
    H := H + ', charset="' + Cfg.Charset + '"';

  Ctx.W.Header.SetValue('WWW-Authenticate', H);
  Ctx.W.Header.SetValue('Cache-Control', 'no-store');
  Ctx.W.Header.SetValue('Vary', 'Authorization');
  Ctx.Status(401);
end;

procedure DefaultBadRequest(Ctx: THTTPRouterContext);
begin
  Ctx.Status(400);
end;

function DefaultBasicAuthConfig: TBasicAuthConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Next := nil;
  Result.Users := nil;
  Result.Authorizer := nil;
  Result.Realm := 'Restricted';
  Result.Charset := 'UTF-8';
  Result.HeaderLimit := 8192;
  Result.Unauthorized := nil;
  Result.BadRequest := nil;
end;

function ConstTimeEquals(const A, B: rawbytestring): boolean;
var
  I: SizeInt;
  Diff: Byte;
begin
  if Length(A) <> Length(B) then Exit(False);
  Diff := 0;
  for I := 1 to Length(A) do
    Diff := Diff or (Ord(A[I]) xor Ord(B[I]));
  Result := (Diff = 0);
end;

function LooksHex(const S: string): boolean;
var
  I: SizeInt;
  C: Char;
begin
  if S = '' then Exit(False);
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if not (C in ['0'..'9','a'..'f','A'..'F']) then Exit(False);
  end;
  Result := True;
end;

function HexToRawBytes(const Hex: string; out B: rawbytestring): boolean;
var
  I, N: Integer;
  ByteVal: Integer;
  Pair: string;
begin
  Result := False;
  B := '';
  if (Hex = '') or ((Length(Hex) mod 2) <> 0) then Exit(False);
  N := Length(Hex) div 2;
  SetLength(B, N);
  for I := 0 to N - 1 do
  begin
    Pair := Copy(Hex, I * 2 + 1, 2);
    if not TryStrToInt('$' + Pair, ByteVal) then Exit(False);
    B[I + 1] := Char(ByteVal and $FF);
  end;
  Result := True;
end;

function OpenSSL_EVP_Digest(const Alg: PEVP_MD; const Data: rawbytestring; out Digest: rawbytestring): boolean;
var
  Ctx: PEVP_MD_CTX;
  Buf: array[0..63] of Byte;
  Len: cuint;
begin
  Result := False;
  Digest := '';

  if not Assigned(Alg) then Exit(False);

  Ctx := EVP_MD_CTX_create();
  if Ctx = nil then Exit(False);
  try
    if EVP_DigestInit(Ctx, Alg) <> 1 then Exit(False);
    if Length(Data) > 0 then
      if EVP_DigestUpdate(Ctx, @Data[1], Length(Data)) <> 1 then Exit(False);
    Len := 0;
    if EVP_DigestFinal(Ctx, @Buf[0], @Len) <> 1 then Exit(False);

    SetLength(Digest, Len);
    if Len > 0 then
      Move(Buf[0], Digest[1], Len);
    Result := True;
  finally
    EVP_MD_CTX_free(Ctx);
  end;
end;

function SHA256Bytes(const S: rawbytestring; out D: rawbytestring): boolean;
begin
  {$IF declared(EVP_sha256)}
  Result := OpenSSL_EVP_Digest(EVP_sha256(), S, D);
  {$ELSE}
  D := '';
  Result := False;
  {$ENDIF}
end;

function SHA512Bytes(const S: rawbytestring; out D: rawbytestring): boolean;
begin
  {$IF declared(EVP_sha512)}
  Result := OpenSSL_EVP_Digest(EVP_sha512(), S, D);
  {$ELSE}
  D := '';
  Result := False;
  {$ENDIF}
end;

function ParseStoredPassword(const Stored: string): TParsedPass;
var
  S, Body: string;
  R: rawbytestring;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Valid := False;

  S := Trim(Stored);
  if S = '' then Exit;

  // bcrypt
  if (LeftStr(S, 4) = '$2a$') or (LeftStr(S, 4) = '$2b$') or (LeftStr(S, 4) = '$2y$') then
  begin
    Result.Kind := pkBcrypt;
    Result.BcryptHash := S;
    Result.Valid := True;
    Exit;
  end;

  // {SHA256} / {SHA512}
  if StartsText('{SHA256}', UpperCase(S)) then
  begin
    Body := Copy(S, Length('{SHA256}') + 1, MaxInt);
    Body := Trim(Body);

    // hex?
    if (Length(Body) = 64) and LooksHex(Body) then
    begin
      Result.Kind := pkSHA256;
      Result.Valid := HexToRawBytes(Body, Result.Digest) and (Length(Result.Digest) = 32);
      Exit;
    end;

    // base64
    if Base64DecodeStdOrRaw(Body, R) and (Length(R) = 32) then
    begin
      Result.Kind := pkSHA256;
      Result.Digest := R;
      Result.Valid := True;
      Exit;
    end;

    Exit; // invalid
  end;

  if StartsText('{SHA512}', UpperCase(S)) then
  begin
    Body := Copy(S, Length('{SHA512}') + 1, MaxInt);
    Body := Trim(Body);

    if (Length(Body) = 128) and LooksHex(Body) then
    begin
      Result.Kind := pkSHA512;
      Result.Valid := HexToRawBytes(Body, Result.Digest) and (Length(Result.Digest) = 64);
      Exit;
    end;

    if Base64DecodeStdOrRaw(Body, R) and (Length(R) = 64) then
    begin
      Result.Kind := pkSHA512;
      Result.Digest := R;
      Result.Valid := True;
      Exit;
    end;

    Exit;
  end;

  // raw sha256 (hex or base64)
  if (Length(S) = 64) and LooksHex(S) then
  begin
    Result.Kind := pkSHA256;
    Result.Valid := HexToRawBytes(S, Result.Digest) and (Length(Result.Digest) = 32);
    Exit;
  end;

  if (Length(S) >= 43) and (Length(S) <= 44) then
  begin
    if Base64DecodeStdOrRaw(S, R) and (Length(R) = 32) then
    begin
      Result.Kind := pkSHA256;
      Result.Digest := R;
      Result.Valid := True;
      Exit;
    end;
  end;

  // default plain
  Result.Kind := pkPlain;
  Result.Plain := Stored;
  Result.Valid := True;
end;

function VerifyPassword(const Stored: string; const PlainPass: string): boolean;
var
  P: TParsedPass;
  Dig, Want: rawbytestring;
  PlainBytes: rawbytestring;
begin
  Result := False;

  P := ParseStoredPassword(Stored);
  if not P.Valid then Exit(False);

  case P.Kind of
    pkPlain:
      Exit(P.Plain = PlainPass);

    pkSHA256:
      begin
        PlainBytes := UTF8Encode(PlainPass);
        if not SHA256Bytes(PlainBytes, Dig) then Exit(False);
        Want := P.Digest;
        Exit(ConstTimeEquals(Dig, Want));
      end;

    pkSHA512:
      begin
        PlainBytes := UTF8Encode(PlainPass);
        if not SHA512Bytes(PlainBytes, Dig) then Exit(False);
        Want := P.Digest;
        Exit(ConstTimeEquals(Dig, Want));
      end;

    pkBcrypt:
      begin
        {$IFDEF USE_BCRYPT}
        // Result := BcryptVerify(PlainPass, P.BcryptHash);
        {$ELSE}
        Result := False;
        {$ENDIF}
      end;
  end;
end;

function BasicAuth(const Cfg: TBasicAuthConfig): TRouterMiddleware;
var
  LocalCfg: TBasicAuthConfig;

  function MakeAuthorizerFromUsers(Users: TStringList): TBasicAuthAuthorizer;
  begin
    Result :=
      function(const User, Pass: string; Ctx: THTTPRouterContext): boolean
      var
        Stored: string;
      begin
        Result := False;
        if Users = nil then Exit(False);

        Stored := Users.Values[User];
        if Stored = '' then Exit(False);

        Result := VerifyPassword(Stored, Pass);
      end;
  end;

begin
  LocalCfg := Cfg;

  if LocalCfg.Realm = '' then LocalCfg.Realm := 'Restricted';

  if (LocalCfg.Charset <> '') and (UpperCase(LocalCfg.Charset) <> 'UTF-8') then
    raise Exception.Create('basicauth: charset must be UTF-8');

  if LocalCfg.HeaderLimit <= 0 then LocalCfg.HeaderLimit := 8192;

  if not Assigned(LocalCfg.BadRequest) then
    LocalCfg.BadRequest := @DefaultBadRequest;

  if not Assigned(LocalCfg.Unauthorized) then
    LocalCfg.Unauthorized :=
      procedure(Ctx: THTTPRouterContext)
      begin
        DefaultUnauthorized(LocalCfg, Ctx);
      end;

  if not Assigned(LocalCfg.Authorizer) then
    LocalCfg.Authorizer := MakeAuthorizerFromUsers(LocalCfg.Users);

  Result :=
    procedure(C: TObject)
    var
      Ctx: THTTPRouterContext;
      RawAuth, Auth, Rest: string;
      RawCreds: rawbytestring;
      Creds: string;
      P: SizeInt;
      User, Pass: string;
    begin
      Ctx := THTTPRouterContext(C);

      if Assigned(LocalCfg.Next) and LocalCfg.Next(Ctx) then
      begin
        Ctx.Next;
        Exit;
      end;

      RawAuth := Ctx.Header('Authorization');
      if RawAuth = '' then
      begin
        LocalCfg.Unauthorized(Ctx);
        Ctx.Abort;
        Exit;
      end;

      if Length(RawAuth) > LocalCfg.HeaderLimit then
      begin
        Ctx.Status(431);
        Ctx.Abort;
        Exit;
      end;

      if not IsAsciiPrintableOrTab(RawAuth) then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      Auth := TrimSpace(RawAuth);
      if Auth = '' then
      begin
        LocalCfg.Unauthorized(Ctx);
        Ctx.Abort;
        Exit;
      end;

      if (Length(Auth) < Length(BASIC_SCHEME)) or (not StartsWithCaseInsensitive(Auth, BASIC_SCHEME)) then
      begin
        LocalCfg.Unauthorized(Ctx);
        Ctx.Abort;
        Exit;
      end;

      Rest := Copy(Auth, Length(BASIC_SCHEME) + 1, MaxInt);
      if (Length(Rest) < 2) or (Rest[1] <> ' ') or (Rest[2] = ' ') then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      Rest := Copy(Rest, 2, MaxInt);
      if IndexOfAnySpace(Rest) <> 0 then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      if not Base64DecodeStdOrRaw(Rest, RawCreds) then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      Creds := UTF8ToUnicodeString(RawCreds);

      P := Pos(':', Creds);
      if P <= 0 then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      User := Copy(Creds, 1, P - 1);
      Pass := Copy(Creds, P + 1, MaxInt);

      if ContainsCTL(User) or ContainsCTL(Pass) then
      begin
        LocalCfg.BadRequest(Ctx);
        Ctx.Abort;
        Exit;
      end;

      if LocalCfg.Authorizer(User, Pass, Ctx) then
      begin
        if Assigned(Ctx.R) and Assigned(Ctx.R.Context) then
          Ctx.R.Context.SetValue('BasicAuthUsername', User);

        Ctx.Next;
        Exit;
      end;

      LocalCfg.Unauthorized(Ctx);
      Ctx.Abort;
    end;
end;

end.
