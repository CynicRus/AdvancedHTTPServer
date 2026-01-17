program CalculatorServer;

{$MODE OBJFPC}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF} Classes, SysUtils, DateUtils, AdvancedHTTPServer;

function LoadFileAsString(const FileName: string): string;
var
  SL: TStringList;
begin
  Result := '';
  if not FileExists(FileName) then Exit;
  SL := TStringList.Create;
  try
    SL.LoadFromFile(FileName);
    Result := SL.Text;
  finally
    SL.Free;
  end;
end;

function LoggingMiddleware(Next: THandlerFunc): THandlerFunc;
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    var
      StartTime: TDateTime;
      Duration: int64;
      Proto: string;
    begin
      StartTime := Now;
      if R.TLS then  Proto := 'HTTPS'
      else
        Proto := 'HTTP';
      WriteLn(FormatDateTime('[yyyy-mm-dd hh:nn:ss]', StartTime), ' ',
      Proto, ' ', R.Method, ' ', R.Path, ' from ', R.RemoteAddr);
      Next(W, R);  // Вызываем следующий обработчик

      Duration := MilliSecondsBetween(Now, StartTime);
      WriteLn('  Completed in ', Duration, 'ms');
    end;

  end;

  function RecoveryMiddleware(Next: THandlerFunc): THandlerFunc;
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    begin
      try
        Next(W, R);
      except
        on E: Exception do
        begin
          WriteLn('PANIC: ', E.Message);
          if not W.HeadersSent then
          begin
            W.Header.SetValue('Content-Type', 'text/plain');
            W.WriteHeader(500);
            W.Write('500 Internal Server Error'#13#10);
            W.Write('The server encountered an error and could not complete your request.');
          end;
        end;
      end;
    end;

  end;


procedure CalcHandler(W: TResponseWriter; R: TRequest);
var
  Content: string;
begin
  Content := LoadFileAsString('calculator/index.html');
  if Content = '' then
  begin
    W.WriteHeader(404);
    W.Write('Calculator UI not found');
    Exit;
  end;
  W.Header.SetValue('Content-Type', 'text/html; charset=utf-8');
  W.Write(Content);
end;

var
  Srv: THTTPServer;
begin
  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);
    Srv.HandleFunc('/', @CalcHandler);

    WriteLn('Starting Calculator Web App on http://localhost:8080');
    WriteLn('Make sure "calculator/index.html" exists in the current directory!');
    Srv.ListenAndServe(':8080');
  finally
    Srv.Free;
  end;
end.
