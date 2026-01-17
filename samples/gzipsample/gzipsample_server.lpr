program gzipsample_server;

{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils,
  Classes,
  DateUtils,
  fpjson,
  zbase,
  zlib1,
  AdvancedHTTPServer;

type
  TByteArray = array[0..0] of byte;
  PByteArray = ^TByteArray;

  function LowerHeader(const R: TRequest; const Name: string): string;
    begin
      Result := LowerCase(Trim(R.Header.GetValue(Name)));
    end;

    function StringToBytesRaw(const S: RawByteString): TBytes;
    var
      L: SizeInt;
    begin
      L := Length(S);
      SetLength(Result, L);
      if L > 0 then
        Move(S[1], Result[0], L);
    end;

    function BytesToRawString(const B: TBytes): RawByteString;
    var
      L: SizeInt;
    begin
      L := Length(B);
      SetLength(Result, L);
      if L > 0 then
        Move(B[0], Result[1], L);
    end;

  function GzipDecompressRaw(const GzData: RawByteString): RawByteString;
  const
    OUT_CHUNK = 8192;
  var
    strm: z_stream;
    inBytes: TBytes;
    outBuf: array[0..OUT_CHUNK-1] of Byte;
    have: Integer;
    outBytes: TBytes;
    outPos: SizeInt;
    err: Integer;
  begin
    if Length(GzData) = 0 then
      Exit('');

    inBytes := StringToBytesRaw(GzData);

    FillChar(strm, SizeOf(strm), 0);
    strm.next_in := @inBytes[0];
    strm.avail_in := Length(inBytes);

    // 16+MAX_WBITS
    err := inflateInit2_(strm, 16 + MAX_WBITS, ZLIB_VERSION, SizeOf(z_stream));
    if err <> Z_OK then
      raise Exception.CreateFmt('inflateInit2 failed: %d', [err]);

    outPos := 0;
    SetLength(outBytes, 0);

    try
      repeat
        strm.next_out := @outBuf[0];
        strm.avail_out := SizeOf(outBuf);

        err := inflate(strm, Z_NO_FLUSH);

        if (err <> Z_OK) and (err <> Z_STREAM_END) then
          raise Exception.CreateFmt('inflate failed: %d', [err]);

        have := Integer(SizeOf(outBuf) - strm.avail_out);
        if have > 0 then
        begin
          SetLength(outBytes, outPos + have);
          Move(outBuf[0], outBytes[outPos], have);
          Inc(outPos, have);
        end;
      until err = Z_STREAM_END;

    finally
      inflateEnd(strm);
    end;

    Result := BytesToRawString(outBytes);
  end;

  function GzipCompressRaw(const Plain: RawByteString; Level: Integer = 6): RawByteString;
  const
    OUT_CHUNK = 8192;
  var
    strm: z_stream;
    inBytes: TBytes;
    outBuf: array[0..OUT_CHUNK-1] of Byte;
    have: Integer;
    outBytes: TBytes;
    outPos: SizeInt;
    err: Integer;
  begin
    inBytes := StringToBytesRaw(Plain);

    FillChar(strm, SizeOf(strm), 0);
    if Length(inBytes) > 0 then
    begin
      strm.next_in := @inBytes[0];
      strm.avail_in := Length(inBytes);
    end;

    // 16+MAX_WBITS
    err := deflateInit2_(strm, Level, Z_DEFLATED, 16 + MAX_WBITS, DEF_MEM_LEVEL,
                         Z_DEFAULT_STRATEGY, ZLIB_VERSION, SizeOf(z_stream));
    if err <> Z_OK then
      raise Exception.CreateFmt('deflateInit2 failed: %d', [err]);

    outPos := 0;
    SetLength(outBytes, 0);

    try
      repeat
        strm.next_out := @outBuf[0];
        strm.avail_out := SizeOf(outBuf);

        err := deflate(strm, Z_FINISH);

        if (err <> Z_OK) and (err <> Z_STREAM_END) then
          raise Exception.CreateFmt('deflate failed: %d', [err]);

        have := Integer(SizeOf(outBuf) - strm.avail_out);
        if have > 0 then
        begin
          SetLength(outBytes, outPos + have);
          Move(outBuf[0], outBytes[outPos], have);
          Inc(outPos, have);
        end;
      until err = Z_STREAM_END;

    finally
      deflateEnd(strm);
    end;

    Result := BytesToRawString(outBytes);
  end;

  // === Обработчик API ===

function HexPrefix(const S: RawByteString; N: Integer): string;
var
  i, L: Integer;
begin
  L := Length(S);
  if N > L then N := L;
  Result := '';
  for i := 1 to N do
    Result += IntToHex(Byte(S[i]), 2) + ' ';
  Result := Trim(Result);
end;

procedure DebugDumpBody(const R: TRequest);
var
  b: RawByteString;
begin
  b := RawByteString(R.Body);
  WriteLn('R.Body length=', Length(b));
  WriteLn('R.Body first bytes=', HexPrefix(b, 16));
end;
  procedure APIHandler(W: TResponseWriter; R: TRequest);
  var
    JSON: TJSONObject;
    ResponseTextUTF8: rawbytestring;
    AcceptEncoding, ContentEncoding: string;
    ReqBodyRaw: rawbytestring;
    RespGz: rawbytestring;
  begin
    AcceptEncoding := LowerHeader(R, 'accept-encoding');
    ContentEncoding := LowerHeader(R, 'content-encoding');
    DebugDumpBody(R);
    WriteLn('zlibVersion: ', zlibVersion());
    WriteLn('compile ZLIB_VERSION: ', ZLIB_VERSION);
    ReqBodyRaw := rawbytestring(R.Body);

    // если запрос gzipped — распаковать
    if ContentEncoding = 'gzip' then
      ReqBodyRaw := GzipDecompressRaw(ReqBodyRaw);

    // собрать JSON
    JSON := TJSONObject.Create;
    try
      JSON.Add('message', 'Hello from Gzip Server!');
      JSON.Add('your_data', string(ReqBodyRaw));
      JSON.Add('timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
      ResponseTextUTF8 := UTF8Encode(JSON.AsJSON);
    finally
      JSON.Free;
    end;

    if Pos('gzip', AcceptEncoding) > 0 then
    begin
      RespGz := GzipCompressRaw(ResponseTextUTF8);

      W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
      W.Header.SetValue('Content-Encoding', 'gzip');
      W.Header.SetValue('Content-Length', IntToStr(Length(RespGz)));

      W.WriteHeader(200);
      if Length(RespGz) > 0 then
        W.Write(RespGz[1], Length(RespGz));
    end
    else
    begin
      W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
      W.WriteHeader(200);
      W.Write(string(ResponseTextUTF8));
    end;
  end;

  // === Статика ===
  procedure StaticHandler(W: TResponseWriter; R: TRequest);
  var
    FilePath: string;
  begin
    if R.Path = '/' then
      FilePath := 'frontend/index.html'
    else
      FilePath := 'frontend' + R.Path;

    if not FileExists(FilePath) then
    begin
      W.WriteHeader(404);
      W.Write('Not found');
      Exit;
    end;

    ServeFile(W, R, FilePath);
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

  // === Main ===
var
  Srv: THTTPServer;
begin
  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);

    Srv.HandleFunc('/api/gzip', @APIHandler);
    Srv.HandleFunc('/', @StaticHandler);

    WriteLn('Gzip Demo started on http://localhost:3000');
    Srv.ListenAndServe(':3000');
  finally
    Srv.Free;
  end;
end.
