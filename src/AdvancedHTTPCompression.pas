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

unit AdvancedHTTPCompression;

{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, StrUtils,
   zbase,
  ZStdStreams, libbrotli, brotli,
  zlib1, AdvancedHTTPServer;

type
  TCompressionAlgo = (caNone, caZstd, caBrotli, caGzip);

  TCompressionOptions = record
    MinSize: Integer;              // do not compress bodies smaller than this
    Prefer: array of TCompressionAlgo; // priority order
    ZstdLevel: Integer;
    BrotliQuality: Integer;
    BrotliLgWin: Integer;
    GzipLevel: Integer;
  end;

function CompressionMiddleware(const Opt: TCompressionOptions): TMiddleware;

function DefaultCompressionOptions: TCompressionOptions;

implementation

function DefaultCompressionOptions: TCompressionOptions;
begin
  Result.MinSize := 512;
  SetLength(Result.Prefer, 3);
  Result.Prefer[0] := caZstd;
  Result.Prefer[1] := caBrotli;
  Result.Prefer[2] := caGzip;

  Result.ZstdLevel := 3;
  Result.BrotliQuality := 5;
  Result.BrotliLgWin := 22;
  Result.GzipLevel := 6;
end;

function LowerHeader(const R: TRequest; const Name: string): string;
begin
  Result := LowerCase(Trim(R.Header.GetValue(Name)));
end;

function HeaderContainsToken(const H, Token: string): Boolean;
var
  L: string;
begin
  L := ',' + StringReplace(LowerCase(H), ' ', '', [rfReplaceAll]) + ',';
  Result := Pos(',' + LowerCase(Token) + ',', L) > 0;
end;

function PickAlgo(const AcceptEncoding: string; const Prefer: array of TCompressionAlgo): TCompressionAlgo;
var
  I: Integer;
  AE: string;
begin
  AE := LowerCase(AcceptEncoding);

  // if client forbids all (identity;q=0) it's exotic; ignore for now
  // if "*", we may pick first supported
  for I := 0 to High(Prefer) do
  begin
    case Prefer[I] of
      caZstd:
        if HeaderContainsToken(AE, 'zstd') or HeaderContainsToken(AE, '*') then Exit(caZstd);
      caBrotli:
        if HeaderContainsToken(AE, 'br') or HeaderContainsToken(AE, '*') then Exit(caBrotli);
      caGzip:
        if HeaderContainsToken(AE, 'gzip') or HeaderContainsToken(AE, '*') then Exit(caGzip);
    else
      ;
    end;
  end;

  Result := caNone;
end;

function CompressZstd(const InData: AnsiString; Level: Integer): AnsiString;
var
  InMS, OutMS: TMemoryStream;
  ZS: TZCompressionStream;
begin
  Result := '';
  InMS := TMemoryStream.Create;
  OutMS := TMemoryStream.Create;
  try
    if Length(InData) > 0 then
      InMS.WriteBuffer(InData[1], Length(InData));
    InMS.Position := 0;

    ZS := TZCompressionStream.Create(OutMS, Level, False, True, False);
    try
      ZS.CopyFrom(InMS, InMS.Size);
      ZS.Finish;
    finally
      ZS.Free;
    end;

    SetLength(Result, OutMS.Size);
    if OutMS.Size > 0 then
    begin
      OutMS.Position := 0;
      OutMS.ReadBuffer(Result[1], OutMS.Size);
    end;
  finally
    InMS.Free;
    OutMS.Free;
  end;
end;

function CompressBrotli(const InData: AnsiString; Quality, LgWin: Integer): AnsiString;
var
  InMS, OutMS: TMemoryStream;
  BS: TBrotliCompressionStream;
begin
  Result := '';
  InMS := TMemoryStream.Create;
  OutMS := TMemoryStream.Create;
  try
    if Length(InData) > 0 then
      InMS.WriteBuffer(InData[1], Length(InData));
    InMS.Position := 0;

    BS := TBrotliCompressionStream.Create(OutMS, Quality, LgWin, BROTLI_MODE_GENERIC, [brLeaveOpen]);
    try
      BS.CopyFrom(InMS, InMS.Size);
      BS.Finish;
    finally
      BS.Free;
    end;

    SetLength(Result, OutMS.Size);
    if OutMS.Size > 0 then
    begin
      OutMS.Position := 0;
      OutMS.ReadBuffer(Result[1], OutMS.Size);
    end;
  finally
    InMS.Free;
    OutMS.Free;
  end;
end;

function CompressGzip(const InData: AnsiString; Level: Integer): AnsiString;
const
  OUT_CHUNK = 8192;
var
  strm: z_stream;
  outBuf: array[0..OUT_CHUNK-1] of Byte;
  have: Integer;
  outPos: SizeInt;
  err: Integer;
  outBytes: TBytes;
  inBytes: TBytes;

  procedure StringToBytesRaw(const S: AnsiString; out B: TBytes);
  var L: SizeInt;
  begin
    L := Length(S);
    SetLength(B, L);
    if L > 0 then
      Move(S[1], B[0], L);
  end;

begin
  Result := '';
  StringToBytesRaw(InData, inBytes);

  FillChar(strm, SizeOf(strm), 0);
  if Length(inBytes) > 0 then
  begin
    strm.next_in := @inBytes[0];
    strm.avail_in := Length(inBytes);
  end;

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

  SetLength(Result, Length(outBytes));
  if Length(outBytes) > 0 then
    Move(outBytes[0], Result[1], Length(outBytes));
end;

function CompressionMiddleware(const Opt: TCompressionOptions): TMiddleware;
begin
  Result := function(Next: THandlerFunc): THandlerFunc
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    var
      AcceptEnc: string;
      Algo: TCompressionAlgo;
      Body, Comp: AnsiString;
      AlreadyEncoded: Boolean;
      CT: string;
    begin
      // Install hook once per request/response
      W.OnBeforeFinish :=
        procedure(W2: TResponseWriter; R2: TRequest)
        var
          EncName: string;
        begin
          // Do not compress if headers already went out
          if W2.HeadersSent then Exit;

          // Only for buffered body (this server is buffered by default)
          Body := W2.BufferedBody;

          if Length(Body) < Opt.MinSize then Exit;

          // HEAD must not have body
          if UpperCase(R2.Method) = 'HEAD' then Exit;

          // 1xx/204/304 generally no body; minimally protect 101 already handled in server
          if (W2.StatusCode >= 100) and (W2.StatusCode < 200) then Exit;
          if (W2.StatusCode = 204) or (W2.StatusCode = 304) then Exit;

          // If handler already set Content-Encoding, leave it alone
          AlreadyEncoded := Trim(W2.Header.GetValue('Content-Encoding')) <> '';
          if AlreadyEncoded then Exit;

          // Skip binary-ish types optionally (you can relax this)
          CT := LowerCase(Trim(W2.Header.GetValue('Content-Type')));
          if (CT <> '') and
             (Pos('image/', CT) = 1) or (Pos('application/zip', CT) = 1) or
             (Pos('application/octet-stream', CT) = 1) then
            Exit;

          AcceptEnc := LowerHeader(R2, 'accept-encoding');
          Algo := PickAlgo(AcceptEnc, Opt.Prefer);
          if Algo = caNone then Exit;

          case Algo of
            caZstd:
              begin
                Comp := CompressZstd(Body, Opt.ZstdLevel);
                EncName := 'zstd';
              end;
            caBrotli:
              begin
                Comp := CompressBrotli(Body, Opt.BrotliQuality, Opt.BrotliLgWin);
                EncName := 'br';
              end;
            caGzip:
              begin
                Comp := CompressGzip(Body, Opt.GzipLevel);
                EncName := 'gzip';
              end;
          else
            Exit;
          end;

          // If compression didn't help, keep original
          if Length(Comp) >= Length(Body) then Exit;

          // Apply headers
          W2.Header.SetValue('Content-Encoding', EncName);
          W2.Header.SetValue('Vary', 'Accept-Encoding');

          // Content-Length is now unknown (and server may have set it)
          W2.Header.DeleteKey('Content-Length');
          W2.Header.DeleteKey('content-length');

          // Force chunked so we can send compressed data safely
          W2.ForceChunked;

          // Replace body
          W2.SetBufferedBody(Comp);
        end;

      // run user handler
      Next(W, R);
    end;
  end;
end;

end.
