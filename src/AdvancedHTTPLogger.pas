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

unit AdvancedHTTPLogger;

{$mode objfpc}{$H+}{$J-}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, DateUtils,
  AdvancedHTTPServer,
  AdvancedHTTPRouter;

type
  TAccessLogProc = reference to procedure(const Line: string);

  { THTTPLogger }
  THTTPLogger = class
  private
    FLog: TAccessLogProc;

    FRequestIDKey: string;          // ключ в R.Context, напр. "request_id"
    FRequestIDHeader: string;       // fallback: "X-Request-Id"
    FUseRequestID: boolean;

    FSkipPaths: TStringList;        // точные пути, напр. "/health"
    FSkipPrefix: TStringList;       // префиксы, напр. "/static/"
    FMaskQueryKeys: TStringList;    // "token", "password" и т.п.

    function LoggerOrDefault: TAccessLogProc;
    procedure DefaultLog(const Line: string);

    function NowUS: Int64;
    function DurationMS(const StartUS, EndUS: Int64): Int64;

    function GetReqID(Ctx: THTTPRouterContext): string;

    function NormalizeUA(const S: string): string;
    function StripOrMaskQuery(const Path, RawQuery: string): string;

    function ShouldSkip(const Path: string): boolean;
    function SafeOneLine(const S: string): string;

  public
    constructor Create;
    destructor Destroy; override;

    property Log: TAccessLogProc read FLog write FLog;

    property UseRequestID: boolean read FUseRequestID write FUseRequestID;
    property RequestIDKey: string read FRequestIDKey write FRequestIDKey;
    property RequestIDHeader: string read FRequestIDHeader write FRequestIDHeader;

    property SkipPaths: TStringList read FSkipPaths;     // можно Add(...)
    property SkipPrefix: TStringList read FSkipPrefix;   // можно Add(...)
    property MaskQueryKeys: TStringList read FMaskQueryKeys; // можно Add(...)

    function RouterMiddleware: TRouterMiddleware;
  end;

implementation

{ THTTPLogger }

constructor THTTPLogger.Create;
begin
  inherited Create;
  FLog := nil;

  FUseRequestID := True;
  FRequestIDKey := 'request_id';
  FRequestIDHeader := 'X-Request-Id';

  FSkipPaths := TStringList.Create;
  FSkipPaths.CaseSensitive := False;

  FSkipPrefix := TStringList.Create;
  FSkipPrefix.CaseSensitive := False;

  FMaskQueryKeys := TStringList.Create;
  FMaskQueryKeys.CaseSensitive := False;
  FMaskQueryKeys.Add('token');
  FMaskQueryKeys.Add('password');
  FMaskQueryKeys.Add('access_token');
  FMaskQueryKeys.Add('refresh_token');
  FMaskQueryKeys.Add('api_key');
end;

destructor THTTPLogger.Destroy;
begin
  FMaskQueryKeys.Free;
  FSkipPrefix.Free;
  FSkipPaths.Free;
  inherited Destroy;
end;

procedure THTTPLogger.DefaultLog(const Line: string);
begin
  WriteLn(Line);
end;

function THTTPLogger.LoggerOrDefault: TAccessLogProc;
begin
  Result := FLog;
  if not Assigned(Result) then
    Result := @Self.DefaultLog;
end;

function THTTPLogger.NowUS: Int64;
begin
  // DateTimeToUnix is seconds; for ms we can use GetTickCount64,
  // но для кроссплатформенности и простоты возьмём GetTickCount64.
  Result := GetTickCount64 * 1000;
end;

function THTTPLogger.DurationMS(const StartUS, EndUS: Int64): Int64;
begin
  if EndUS <= StartUS then Exit(0);
  Result := (EndUS - StartUS) div 1000;
end;

function THTTPLogger.SafeOneLine(const S: string): string;
var
  T: string;
begin
  T := StringReplace(S, #13, ' ', [rfReplaceAll]);
  T := StringReplace(T, #10, ' ', [rfReplaceAll]);
  Result := Trim(T);
end;

function THTTPLogger.NormalizeUA(const S: string): string;
begin
  Result := SafeOneLine(S);
  if Length(Result) > 200 then
    Result := Copy(Result, 1, 200) + '...';
end;

function THTTPLogger.GetReqID(Ctx: THTTPRouterContext): string;
begin
  Result := '';
  if not FUseRequestID then Exit;

  if Assigned(Ctx.R.Context) and (FRequestIDKey <> '') then
    Result := Ctx.R.Context.GetValue(FRequestIDKey);

  if (Result = '') and (FRequestIDHeader <> '') then
    Result := Ctx.R.Header.GetValue(FRequestIDHeader);
end;

function THTTPLogger.ShouldSkip(const Path: string): boolean;
var
  I: Integer;
  P: string;
begin
  Result := False;

  for I := 0 to FSkipPaths.Count - 1 do
    if SameText(FSkipPaths[I], Path) then
      Exit(True);

  for I := 0 to FSkipPrefix.Count - 1 do
  begin
    P := FSkipPrefix[I];
    if (P <> '') and (LeftStr(Path, Length(P)) = P) then
      Exit(True);
  end;
end;

function THTTPLogger.StripOrMaskQuery(const Path, RawQuery: string): string;
var
  Params: TStringList;
  I: Integer;
  K: string;
begin
  if RawQuery = '' then Exit(Path);

  Params := TStringList.Create;
  try
    Params.StrictDelimiter := True;
    Params.Delimiter := '&';
    Params.DelimitedText := RawQuery;

    for I := 0 to Params.Count - 1 do
    begin
      K := Params.Names[I];
      if (K <> '') and (FMaskQueryKeys.IndexOf(LowerCase(K)) >= 0) then
        Params.ValueFromIndex[I] := '***';
    end;

    Result := Path + '?' + Params.DelimitedText;
  finally
    Params.Free;
  end;
end;

function THTTPLogger.RouterMiddleware: TRouterMiddleware;
begin
  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    StartUS, EndUS: Int64;
    DurMS: Int64;

    Status: Integer;
    Bytes: Int64;

    ReqID: string;
    Logger: TAccessLogProc;

    FullPath: string;
    Line: string;
    Route: string;
    UA: string;
  begin
    if not (C is THTTPRouterContext) then
      raise Exception.Create('Logger middleware: context is not THTTPRouterContext');

    Ctx := THTTPRouterContext(C);

    if ShouldSkip(Ctx.R.Path) then
    begin
      Ctx.Next;
      Exit;
    end;

    Logger := LoggerOrDefault;

    StartUS := NowUS;
    try
      Ctx.Next;
    finally
      EndUS := NowUS;
    end;
    Status := Ctx.W.StatusCode;
    Bytes := Ctx.W.BytesWritten;

    DurMS := DurationMS(StartUS, EndUS);

    ReqID := GetReqID(Ctx);

    FullPath := StripOrMaskQuery(Ctx.R.Path, Ctx.R.RawQuery);
    Route := Ctx.RoutePattern;
    if Route = '' then Route := '-';

    UA := NormalizeUA(Ctx.R.Header.GetValue('User-Agent'));

    Line :=
      '[access] ' +
      FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) +
      ' remote=' + Ctx.R.RemoteAddr +
      ' proto=' + Ctx.R.Proto +
      ' method=' + Ctx.R.Method +
      ' path=' + FullPath +
      ' route=' + Route +
      ' status=' + IntToStr(Status) +
      ' bytes=' + IntToStr(Bytes) +
      ' dur_ms=' + IntToStr(DurMS);

    if ReqID <> '' then
      Line := Line + ' request_id=' + ReqID;

    if UA <> '' then
      Line := Line + ' ua="' + UA + '"';

    Logger(Line);
  end;
end;

end.
