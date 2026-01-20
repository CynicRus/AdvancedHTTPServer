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
unit AdvancedHTTPRecovery;

{$mode objfpc}{$H+}{$J-}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes,
  fpjson,
  AdvancedHTTPServer,
  AdvancedHTTPRouter;

type
  TRecoveryLogProc = reference to procedure(const Line: string);

  { THTTPRecovery }
  THTTPRecovery = class
  private
    FDebug: boolean;
    FExposeExceptionMessage: boolean;
    FLog: TRecoveryLogProc;
    FRequestIDHeader: string;
    FAddRequestID: boolean;
    FPreferJSON: boolean;
    FJSONErrorKey: string;

    function NewRequestID: string;
    procedure DefaultLog(const Line: string);

    function EscapeJSON(const S: string): string;
    function BuildJSONError(const RequestID: string; const E: Exception): TJSONObject;

    procedure WriteRouter500(Ctx: THTTPRouterContext; const E: Exception; const ReqID: string);
    function LoggerOrDefault: TRecoveryLogProc;

  public
    constructor Create;

    property Debug: boolean read FDebug write FDebug;
    property ExposeExceptionMessage: boolean
      read FExposeExceptionMessage write FExposeExceptionMessage;

    property Log: TRecoveryLogProc read FLog write FLog;

    property AddRequestID: boolean read FAddRequestID write FAddRequestID;
    property RequestIDHeader: string read FRequestIDHeader write FRequestIDHeader;

    property PreferJSON: boolean read FPreferJSON write FPreferJSON;

    property JSONErrorKey: string read FJSONErrorKey write FJSONErrorKey;

    // Middleware for server.Use(...)
    function Middleware: TMiddleware;

    // Middleware for router.Use(...)
    function RouterMiddleware: TRouterMiddleware;
  end;

implementation

uses
  DateUtils;

{ THTTPRecovery }

constructor THTTPRecovery.Create;
begin
  inherited Create;
  FDebug := False;
  FExposeExceptionMessage := False;
  FLog := nil;

  FAddRequestID := True;
  FRequestIDHeader := 'X-Request-Id';

  FPreferJSON := True;
  FJSONErrorKey := 'error';
end;

procedure THTTPRecovery.DefaultLog(const Line: string);
begin
  WriteLn(Line);
end;

function THTTPRecovery.LoggerOrDefault: TRecoveryLogProc;
begin
  Result := FLog;
  if not Assigned(Result) then
    Result := @Self.DefaultLog;
end;

function THTTPRecovery.NewRequestID: string;
begin
  Result := IntToHex(DateTimeToUnix(Now), 8) + '-' + IntToHex(Random(MaxInt), 8);
end;

function THTTPRecovery.EscapeJSON(const S: string): string;
var
  I: integer;
  Ch: Char;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    Ch := S[I];
    case Ch of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #8: Result := Result + '\b';
      #9: Result := Result + '\t';
      #10: Result := Result + '\n';
      #12: Result := Result + '\f';
      #13: Result := Result + '\r';
      else
        if Ord(Ch) < 32 then
          Result := Result + '\u' + IntToHex(Ord(Ch), 4)
        else
          Result := Result + Ch;
    end;
  end;
end;

function THTTPRecovery.BuildJSONError(const RequestID: string; const E: Exception): TJSONObject;
var
  Msg: string;
begin
  Result := TJSONObject.Create;
  Msg := 'Internal Server Error';

  Result.Add(FJSONErrorKey, Msg);
  if RequestID <> '' then
    Result.Add('request_id', RequestID);

  if FExposeExceptionMessage then
  begin
    Result.Add('detail', E.Message);
    Result.Add('exception', E.ClassName);
  end;

  if FDebug then
  begin
    if (ExceptAddr <> nil) then
      Result.Add('except_addr', IntToHex(PtrUInt(ExceptAddr), SizeOf(Pointer) * 2));
  end;
end;

procedure THTTPRecovery.WriteRouter500(Ctx: THTTPRouterContext; const E: Exception; const ReqID: string);
var
  Obj: TJSONObject;
  Body: string;
begin
  if Ctx.W.HeadersSent then
  begin
    try
      Ctx.W.Write(#10'Internal Server Error');
    except

    end;
    Ctx.Abort;
    Exit;
  end;

  if FPreferJSON then
  begin
    Obj := BuildJSONError(ReqID, E);
    try
      Ctx.JSON(500, Obj);
    finally
      Obj.Free;
    end;
  end
  else
  begin
    Body := 'Internal Server Error';
    if ReqID <> '' then
      Body := Body + #10 + 'request_id: ' + ReqID;
    if FExposeExceptionMessage then
      Body := Body + #10 + 'error: ' + E.Message;
    Ctx.Text(500, Body);
  end;

  Ctx.Abort;
end;

function THTTPRecovery.RouterMiddleware: TRouterMiddleware;
begin
  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    ReqID: string;
    Line: string;
    Logger: TRecoveryLogProc;
  begin
    if not (C is THTTPRouterContext) then
      raise Exception.Create('Recovery middleware: context is not THTTPRouterContext');

    Ctx := THTTPRouterContext(C);

    Logger := LoggerOrDefault;

    ReqID := '';
    if FAddRequestID then
    begin
      ReqID := Ctx.R.Header.GetValue(FRequestIDHeader);
      if ReqID = '' then
        ReqID := NewRequestID;

      if Assigned(Ctx.R.Context) then
        Ctx.R.Context.SetValue('request_id', ReqID);

      if (not Ctx.W.HeadersSent) and (FRequestIDHeader <> '') then
        Ctx.W.Header.SetValue(FRequestIDHeader, ReqID);
    end;

    try
      Ctx.Next;
    except
      on E: Exception do
      begin
        Line :=
          '[recovery(router)] ' +
          FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) +
          ' remote=' + Ctx.R.RemoteAddr +
          ' proto=' + Ctx.R.Proto +
          ' method=' + Ctx.R.Method +
          ' path=' + Ctx.R.Path;

        if Ctx.RoutePattern <> '' then
          Line := Line + ' route=' + Ctx.RoutePattern;

        if ReqID <> '' then
          Line := Line + ' request_id=' + ReqID;

        Line := Line + ' error="' + E.ClassName + ': ' + E.Message + '"';

        Logger(Line);

        WriteRouter500(Ctx, E, ReqID);
      end;
    end;
  end;
end;

function THTTPRecovery.Middleware: TMiddleware;
begin
  Result := function(Next: THandlerFunc): THandlerFunc
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    var
      ReqID: string;
      Line: string;
      Logger: TRecoveryLogProc;
      Body: string;
    begin
      Logger := LoggerOrDefault;

      ReqID := '';
      if FAddRequestID then
      begin
        ReqID := R.Header.GetValue(FRequestIDHeader);
        if ReqID = '' then
          ReqID := NewRequestID;

        if Assigned(R.Context) then
          R.Context.SetValue('request_id', ReqID);

        if (not W.HeadersSent) and (FRequestIDHeader <> '') then
          W.Header.SetValue(FRequestIDHeader, ReqID);
      end;

      try
        Next(W, R);
      except
        on E: Exception do
        begin
          Line :=
            '[recovery(server)] ' +
            FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) +
            ' remote=' + R.RemoteAddr +
            ' proto=' + R.Proto +
            ' method=' + R.Method +
            ' path=' + R.Path;

          if ReqID <> '' then
            Line := Line + ' request_id=' + ReqID;

          Line := Line + ' error="' + E.ClassName + ': ' + E.Message + '"';

          Logger(Line);

          // Safe 500
          try
            if not W.HeadersSent then
            begin
              if FPreferJSON then
              begin
                W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
                W.WriteHeader(500);
                Body := '{"' + EscapeJSON(FJSONErrorKey) + '":"Internal Server Error"';
                if ReqID <> '' then
                  Body := Body + ',"request_id":"' + EscapeJSON(ReqID) + '"';
                if FExposeExceptionMessage then
                  Body := Body + ',"detail":"' + EscapeJSON(E.Message) + '","exception":"' + EscapeJSON(E.ClassName) + '"';
                Body := Body + '}';
                W.Write(Body);
              end
              else
              begin
                W.Header.SetValue('Content-Type', 'text/plain; charset=utf-8');
                W.WriteHeader(500);
                Body := 'Internal Server Error';
                if ReqID <> '' then Body := Body + #10 + 'request_id: ' + ReqID;
                if FExposeExceptionMessage then Body := Body + #10 + 'error: ' + E.Message;
                W.Write(Body);
              end;
            end
            else
              W.Write(#10'Internal Server Error');
          except

          end;
        end;
      end;
    end;
  end;
end;

end.

