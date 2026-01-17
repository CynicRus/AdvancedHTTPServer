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

unit AdvancedHTTPServer;

{$MODE OBJFPC}{$H+}{$J-}
{$modeSwitch advancedRecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  {$IFDEF UNIX}
  cthreads,
  BaseUnix,
  Unix,
  Linux,
  Sockets, // Standard FPC sockets for Linux
  {$ENDIF}
  {$IFDEF WINDOWS}
  Windows,
  Sockets,
  JwaWinsock2,
  JwaWinBase,
  {$ENDIF}
  SysUtils, StrUtils, Classes, FGL, DateUtils, syncobjs, patched_openssl, ctypes, contnrs, math
  {$IFDEF ENABLE_HTTP2}
  , nghttp2
  {$ENDIF}
  ;

  {$IFDEF LINUX}
// Epoll constants
const
  EPOLL_CTL_ADD = 1;
  EPOLL_CTL_DEL = 2;
  EPOLL_CTL_MOD = 3;
  EPOLLIN = $001;
  EPOLLOUT = $004;
  EPOLLERR = $008;
  EPOLLHUP = $010;
  EPOLLET = 1 shl 31;

type
  epoll_data = record
    case Integer of
      0: (ptr: Pointer);
      1: (fd: Integer);
      2: (u32: Cardinal);
      3: (u64: QWord);
  end;

  epoll_event = packed record
    events: Cardinal;
    data: epoll_data;
  end;

function epoll_create(size: Integer): Integer; cdecl; external 'c' name 'epoll_create';
function epoll_ctl(epfd: Integer; op: Integer; fd: Integer; event: Pointer): Integer; cdecl; external 'c' name 'epoll_ctl';
function epoll_wait(epfd: Integer; events: Pointer; maxevents: Integer; timeout: Integer): Integer; cdecl; external 'c' name 'epoll_wait';
  {$ENDIF}

  // SSL error codes
const
  SSL_ERROR_NONE = 0;
  SSL_ERROR_SSL = 1;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_WANT_X509_LOOKUP = 4;
  SSL_ERROR_SYSCALL = 5;
  SSL_ERROR_ZERO_RETURN = 6;
  SSL_ERROR_WANT_CONNECT = 7;
  SSL_ERROR_WANT_ACCEPT = 8;

  MAX_HEADER_BYTES = 65536;      // 64KB
  MAX_BODY_BYTES = 33554432;     // 32MB
  MAX_CHUNK_SIZE = 16777216;     // 16MB per chunk
  CONNECTION_TIMEOUT = 30;        // seconds
  HEADER_READ_TIMEOUT = 10;       // seconds
  BODY_READ_TIMEOUT = 60;         // seconds

type
  THTTPServer = class;          // forward
  PClientConnection = ^TClientConnection; // forward

  {$IFDEF Linux}
  TSockAddrIn = sockaddr_in;
  {$ENDIF}

  {$IFDEF WINDOWS}
  TIOOperation = (ioRead, ioWrite, ioAccept);

  PIOContext = ^TIOContext;
  TIOContext = record
    Overlapped: TOverlapped;
    Operation: TIOOperation;
    Connection: PClientConnection;
    Buffer: array[0..4095] of Byte;
    BytesTransferred: DWORD;
  end;
  {$ENDIF}

  { TContext }
  TContext = class
  private
    FDeadline: TDateTime;
    FCancelled: boolean;
    FLock: TCriticalSection;
    FValues: TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Cancel;
    function IsCancelled: boolean;
    procedure SetDeadline(D: TDateTime);
    function IsExpired: boolean;
    procedure SetValue(const Key, Value: string);
    function GetValue(const Key: string): string;
  end;

  { THeader }
  THeader = class(TStringList)
  public
    constructor Create;
    procedure AddValue(const Key, Value: string);
    procedure AddRawHeaderLine(const Line: string);
    function GetValue(const Key: string): string;
    function GetAllValuesJoined(const Key: string; const Sep: string): string;
    procedure SetValue(const Key, Value: string);
    procedure DeleteKey(const Key: string);
  end;

  { TTrailer }
  TTrailer = class(THeader)
  end;

  { TRequest }
  TRequest = class
  private
    FCookiesParsed: boolean;
    FCookies: TStringList;
    procedure EnsureCookiesParsed;
  public
    Method: string;
    URL: string;
    Path: string;
    RawQuery: string;
    Proto: string;
    Header: THeader;
    Body: string;
    Trailer: TTrailer;
    RemoteAddr: string;
    TLS: boolean;
    TransferEncoding: array of string;
    ContentLength: int64;
    Context: TContext;
    constructor Create;
    destructor Destroy; override;
    function QueryValue(const Key: string): string;
    procedure ParseQuery(out Params: TStringList);
    function PostFormValue(const Key: string): string;
    procedure ParsePostForm(out Params: TStringList);
    function HasChunkedEncoding: boolean;
    function CookieValue(const Name: string): string;
    function HasCookie(const Name: string): boolean;
    procedure ParseCookies(out Cookies: TStringList);
  end;

  { TResponseWriter }
  TResponseWriter = class
  public
  type
    TCookieSameSite = (ssUnspecified, ssLax, ssStrict, ssNone);
  private
    FConn: PClientConnection;
    FServer: THTTPServer;
    FSocket: integer;
    FSSL: PSSL;
    FUseTLS: boolean;
    FStatus: integer;
    FHeadersSent: boolean;
    FStatusText: string;
    FConnection: string;
    FChunked: boolean;
    FHeader: THeader;
    FTrailer: TTrailer;
    FContentLength: int64;
    FExplicitCL: boolean;
    FBodyBuf: ansistring;
    FBuffered: boolean;
    FTrailersSent: boolean;
    procedure SendRaw(const Buf; Size: integer);
  public
    constructor Create(AConn: PClientConnection; AConnection: string);
    destructor Destroy; override;
    function Header: THeader;
    function Trailer: TTrailer;
    procedure WriteHeader(Code: integer);
    procedure Write(const S: string); overload;
    procedure Write(const Buf; Size: integer); overload;
    procedure SendHeadersIfNeeded;
    procedure SetCookie(const Name, Value: string; const Path: string = '/';
      const Domain: string = ''; Expires: TDateTime = 0; MaxAge: integer = -1;
      Secure: boolean = False; HttpOnly: boolean = True;
      SameSite: TCookieSameSite = ssLax);
    procedure Finish;
    function HeadersSent: boolean;
  end;

  THandlerFunc = reference to procedure(W: TResponseWriter; R: TRequest);
  TMiddleware = reference to function(Next: THandlerFunc): THandlerFunc;

  { TRoute }
  TRoute = record
    Pattern: string;
    Handler: THandlerFunc;
    class operator =(const A, B: TRoute): boolean;
    class operator <>(const A, B: TRoute): boolean;
  end;

  TRouteList = specialize TFPGList<TRoute>;

  { THostRoute }
  THostRoute = record
    Host: string;
    Pattern: string;
    Handler: THandlerFunc;
    class operator =(const A, B: THostRoute): boolean;
    class operator <>(const A, B: THostRoute): boolean;
  end;

  THostRouteList = specialize TFPGList<THostRoute>;

  { TTLSConfig }
  TTLSConfig = record
    Enabled: boolean;
    CertFile: string;
    KeyFile: string;
  end;

  { TConnectionState }
  TConnectionState = (csSSLHandshake, csReadingHeaders, csReadingBody,
    csReadingChunks, csProcessing, csClosed);

  { TPendingRequest }
  PPendingRequest = ^TPendingRequest;

  TPendingRequest = record
    Head: ansistring;
    Body: ansistring;
  end;

  {$IFDEF ENABLE_HTTP2}
  type
    PHTTP2StreamData = ^THTTP2StreamData;
    THTTP2StreamData = record
      StreamID: nghttp2_stream_id;
      Request: TRequest;
      Connection: PClientConnection;
      HeadersComplete: Boolean;
      DataComplete: Boolean;
      ResponseData: AnsiString; // Buffer for simple responses
    end;
  {$ENDIF}

  { TClientConnection }
  TClientConnection = record
    Sock: integer;
    SSL: PSSL;
    UseTLS: boolean;
    Addr: string;
    State: TConnectionState;
    // Unified buffer for plaintext application data (HTTP)
    PlainInBuf: ansistring;
    OutBuf: ansistring; // Used for buffering writes (encrypted data for TLS, plaintext for HTTP)
    CurrentRequest: TRequest;
    CurrentWriter: TResponseWriter;
    KeepAlive: boolean;
    PipelineRequests: TList;  // List of PPendingRequest
    LastActivity: TDateTime;
    LastStateChange: TDateTime;
    ChunkBytesRemaining: int64;
    BodyBytesRemaining: int64;
    ExpectingContinue: boolean;
    HeaderBytesRead: int64;
    BodyBytesRead: int64;
    SSLHandshakeStarted: boolean;
    HeaderStartTime: TDateTime; // Slow header attack protection
    Server: THTTPServer; // Ref to server for routing

    // Memory BIO (used on both Linux and Windows now)
    ReadBIO: PBIO;
    WriteBIO: PBIO;
    HandshakeDone: Boolean;

    {$IFDEF WINDOWS}
    // IOCP specific
    IOContext: PIOContext;
    WritePending: Boolean;
    WriteIOContext: PIOContext;
    {$ENDIF}
    {$IFDEF ENABLE_HTTP2}
    HTTP2Session: Pnghttp2_session;
    HTTP2Enabled: Boolean;
    HTTP2PrefaceReceived: Boolean;
    HTTP2Streams: TFPHashList; // Stream ID -> THTTPRequest mapping
    {$ENDIF}
  end;

  { TSSLHandshakeThread }
  TSSLHandshakeThread = class(TThread)
  private
    FServer: TObject;
    {$IFDEF LINUX}
    FConn: PClientConnection;
    {$ENDIF}
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TObject; AConn: PClientConnection = nil);
  end;

  TConnectionList = specialize TFPGList<PClientConnection>;

  { THTTPServer }
  THTTPServer = class
  private
    FRoutes: TRouteList;
    FHostRoutes: THostRouteList;
    FMiddlewares: array of TMiddleware;
    FServerSock: integer;
    FActiveConnections: integer;
    FConnectionsLock: TCriticalSection;
    FTLSConfig: TTLSConfig;
    FSSLCtx: PSSL_CTX;
    FShutdownEvent: PRTLEvent;
    FConnectionTimeout: integer;
    FHeaderReadTimeout: integer;
    FBodyReadTimeout: integer;
    FMaxHeaderBytes: int64;
    FMaxBodyBytes: int64;
    FConnections: TConnectionList;
    {$IFDEF LINUX}
    FEpollFd: Integer;
    FServerIsTLS: Boolean;
    procedure ModEpoll(Sock: Integer; Conn: PClientConnection; Events: Cardinal);
    procedure EnableWriteNotifications(Conn: PClientConnection);
    procedure DisableWriteNotifications(Conn: PClientConnection);
    procedure HandleEpollWrite(Conn: PClientConnection);
    // New Linux helpers
    procedure FlushWriteBIOToOutBuf(Conn: PClientConnection);
    procedure ProcessSSL(Conn: PClientConnection);
    {$ENDIF}
    {$IFDEF WINDOWS}
    FIOCPHandle: THandle;
    procedure FlushWriteBIO(Conn: PClientConnection);
    procedure ProcessSSL(Conn: PClientConnection);
    {$ENDIF}
    {$IFDEF ENABLE_HTTP2}
    function InitHTTP2Session(Conn: PClientConnection): Boolean;
    {$ENDIF}
    procedure ProcessRequestsFromBuffer(Conn: PClientConnection);

    function FindHandlerByHost(const Host, Path: string; out Handler: THandlerFunc;
      out RedirectTo: string): boolean;
    function FindHandlerOrRedirect(const Path: string; out Handler: THandlerFunc;
      out RedirectTo: string): boolean;
    procedure ParseRequestLine(const Head: ansistring; const ClientAddr: string;
      UseTLS: boolean; out R: TRequest);
    function TryExtractRequest(var InBuf: ansistring; out Head, Body: ansistring;
      out NeedMoreData: boolean): boolean;
    function ReadChunkedBody(Conn: PClientConnection): boolean;
    procedure ProcessRequest(Conn: PClientConnection);
    procedure SendContinueResponse(Conn: PClientConnection);
    procedure SendErrorResponse(Conn: PClientConnection; Code: integer;
      const Msg: string);
    procedure CloseConnection(Conn: PClientConnection);
    procedure CheckConnectionTimeouts;
    procedure IncConnections;
    procedure DecConnections;
    function InitSSL: boolean;
    procedure CleanupSSL;
    procedure WaitForConnections;
    procedure StartSSLHandshake(Conn: PClientConnection);
    {$IFDEF LINUX}
    procedure InitEpoll;
    procedure AddToEpoll(Sock: Integer; Conn: PClientConnection);
    procedure RemoveFromEpoll(Sock: Integer);
    procedure RunEpollLoop;
    procedure HandleEpollRead(Conn: PClientConnection);
    {$ENDIF}
    {$IFDEF WINDOWS}
    procedure InitIOCP;
    procedure AssociateWithIOCP(Sock: TSocket; Conn: PClientConnection);
    procedure PostRead(Conn: PClientConnection);
    procedure RunIOCPLoop;
    {$ENDIF}
  public
    constructor Create;
    destructor Destroy; override;
    procedure HandleFunc(const Pattern: string; Handler: THandlerFunc);
    procedure HandleFuncHost(const Host, Pattern: string; Handler: THandlerFunc);
    procedure Use(Middleware: TMiddleware);
    procedure ListenAndServe(const Addr: string);
    procedure ListenAndServeTLS(const Addr: string; const CertFile, KeyFile: string);
    procedure Shutdown;
    function ActiveConnections: integer;
    property ConnectionTimeout: integer read FConnectionTimeout write FConnectionTimeout;
    property MaxHeaderBytes: int64 read FMaxHeaderBytes write FMaxHeaderBytes;
    property MaxBodyBytes: int64 read FMaxBodyBytes write FMaxBodyBytes;
  end;

{$IFDEF WINDOWS}
  // IOCP Loop Thread
  type
    TIOCPLoopThread = class(TThread)
    private
      FServer: THTTPServer;
    protected
      procedure Execute; override;
    public
      constructor Create(AServer: THTTPServer);
    end;
{$ENDIF}

function FileServer(const Root: string): THandlerFunc;
procedure ServeFile(W: TResponseWriter; R: TRequest; const FilePath: string);

var
  ShutdownRequested: boolean = False;
  SSLInitialized: boolean = False;

implementation

{ TIOCPLoopThread }

{$IFDEF WINDOWS}
  constructor TIOCPLoopThread.Create(AServer: THTTPServer);
  begin
    inherited Create(False);
    FServer := AServer;
    FreeOnTerminate := False;
  end;

  procedure TIOCPLoopThread.Execute;
  begin
    FServer.RunIOCPLoop;
  end;
{$ENDIF}

{ --- Socket Wrappers --- }

function SysClose(Sock: integer): integer;
begin
  {$IFDEF WINDOWS}
  Result := closesocket(TSocket(Sock));
  {$ELSE}
  Result := fpClose(Sock);
  {$ENDIF}
end;

function SysSend(Sock: integer; var Buf; Len, Flags: integer): integer;
begin
  {$IFDEF WINDOWS}
  Result := send(TSocket(Sock), Buf, Len, Flags);
  {$ELSE}
  Result := fpsend(Sock, @Buf, Len, Flags);
  {$ENDIF}
end;

function SysRecv(Sock: integer; Buf: Pointer; Len, Flags: integer): integer;
begin
  {$IFDEF WINDOWS}
  Result := recv(TSocket(Sock), Buf, Len, Flags);
  {$ELSE}
  Result := fprecv(Sock, Buf, Len, Flags);
  {$ENDIF}
end;

function SysAccept(Sock: integer; var Addr; var AddrLen: integer): integer;
begin
  {$IFDEF WINDOWS}
  Result := accept(TSocket(Sock), @Addr, @AddrLen);
  {$ELSE}
  Result := fpaccept(Sock, @Addr, @AddrLen);
  {$ENDIF}
end;

function SysSetNonBlocking(Sock: integer; NonBlocking: boolean): boolean;
  {$IFDEF WINDOWS}
var
  Mode: u_long;
  {$ELSE}
var
  Flags: longint;
  {$ENDIF}
begin
  Result := True;
  {$IFDEF WINDOWS}
  Mode := Ord(NonBlocking);
  if ioctlsocket(TSocket(Sock), FIONBIO, Mode) = SOCKET_ERROR then
    Result := False;
  {$ELSE}
  Flags := fpfcntl(Sock, F_GETFL, 0);
  if Flags < 0 then Exit(False);

  if NonBlocking then
    Result := (fpfcntl(Sock, F_SETFL, Flags or O_NONBLOCK) >= 0)
  else
    Result := (fpfcntl(Sock, F_SETFL, Flags and (not O_NONBLOCK)) >= 0);
  {$ENDIF}
end;

class operator TRoute.=(const A, B: TRoute): boolean;
begin
  Result :=
    (A.Pattern = B.Pattern);
end;

class operator TRoute.<>(const A, B: TRoute): boolean;
begin
  Result := not (A = B);
end;

class operator THostRoute.=(const A, B: THostRoute): boolean;
begin
  Result := (A.Host = B.Host) and (A.Pattern = B.Pattern);
end;

class operator THostRoute.<>(const A, B: THostRoute): boolean;
begin
  Result := not (A = B);
end;

procedure LogSSLError(const Prefix: string);
var
  ErrCode: cardinal;
  ErrMsg: ansistring;
begin
  ErrCode := ERRGetError();
  while ErrCode <> 0 do
  begin
    ERRErrorString(ErrCode, ErrMsg, Length(ErrMsg));
    WriteLn(Prefix, ': ', ErrMsg);
    ErrCode := ERRGetError();
  end;
end;

{$IFDEF ENABLE_HTTP2}
// ALPN Callback
function ALPNSelectCallback(ssl: PSSL; out_proto: PPByte; outlen: PByte;
                            const in_proto: PByte; inlen: cuint; arg: Pointer): cint; cdecl;
const
  H2Protocol: PAnsiChar = #2'h2';
begin
  if (inlen >= 3) and (in_proto[0] = 2) and (in_proto[1] = Ord('h')) and (in_proto[2] = Ord('2')) then
  begin
    out_proto^ := PByte(H2Protocol) + 1;
    outlen^ := 2;
    Exit(SSL_TLSEXT_ERR_OK);
  end;
  Exit(SSL_TLSEXT_ERR_NOACK);
end;

// HTTP/2 send callback
function HTTP2SendCallback(session: Pnghttp2_session; const data: PByte;
                           length: csize_t; flags: cuint; user_data: Pointer): nghttp2ssize; cdecl;
var
  Conn: PClientConnection;
  Ret: Integer;
begin
  Conn := PClientConnection(user_data);

  {$IFDEF WINDOWS}
  if Conn^.UseTLS then
  begin
     // Memory BIO flow
     Ret := SSL_write(Conn^.SSL, data, length);
     if Ret < 0 then Exit(NGHTTP2_ERR_CALLBACK_FAILURE);
  end
  else
  {$ENDIF}
  if Conn^.UseTLS then
    Ret := SSL_write(Conn^.SSL, data, length)
  else
    Ret := SysSend(Conn^.Sock, data^, length, 0);

  if Ret < 0 then
    Exit(NGHTTP2_ERR_CALLBACK_FAILURE);

  Result := Ret;
end;

// HTTP/2 on_frame_recv callback
function HTTP2OnFrameRecvCallback(session: Pnghttp2_session; const frame: Pnghttp2_frame;
                                  user_data: Pointer): cint; cdecl;
var
  Conn: PClientConnection;
  FrameHdr: Pnghttp2_frame_hd;
begin
  Conn := PClientConnection(user_data);
  FrameHdr := Pnghttp2_frame_hd(frame);

  case FrameHdr^._type of
    NGHTTP2_HEADERS:
      WriteLn('HTTP/2 HEADERS frame received on stream ', FrameHdr^.stream_id);
    NGHTTP2_DATA:
      WriteLn('HTTP/2 DATA frame received on stream ', FrameHdr^.stream_id);
  end;

  Result := 0;
end;

// HTTP/2 on_begin_headers callback
function HTTP2OnBeginHeadersCallback(session: Pnghttp2_session; const frame: Pnghttp2_frame;
                                     user_data: Pointer): cint; cdecl;
var
  Conn: PClientConnection;
  StreamData: PHTTP2StreamData;
  FrameHdr: Pnghttp2_frame_hd;
begin
  Conn := PClientConnection(user_data);
  FrameHdr := Pnghttp2_frame_hd(frame);

  New(StreamData);
  StreamData^.StreamID := FrameHdr^.stream_id;
  StreamData^.Request := TRequest.Create;
  StreamData^.Request.Proto := 'HTTP/2.0';
  StreamData^.Request.TLS := Conn^.UseTLS;
  StreamData^.Request.RemoteAddr := Conn^.Addr;
  StreamData^.Connection := Conn;
  StreamData^.HeadersComplete := False;
  StreamData^.DataComplete := False;
  StreamData^.ResponseData := '';

  nghttp2_session_set_stream_user_data(session, FrameHdr^.stream_id, StreamData);
  Conn^.HTTP2Streams.Add(IntToStr(FrameHdr^.stream_id), StreamData);

  Result := 0;
end;

// HTTP/2 on_header callback
function HTTP2OnHeaderCallback(session: Pnghttp2_session; const frame: Pnghttp2_frame;
                               const name: PByte; namelen: csize_t;
                               const value: PByte; valuelen: csize_t;
                               flags: cuint; user_data: Pointer): cint; cdecl;
var
  StreamData: PHTTP2StreamData;
  FrameHdr: Pnghttp2_frame_hd;
  HeaderName, HeaderValue: string;
begin
  FrameHdr := Pnghttp2_frame_hd(frame);
  StreamData := PHTTP2StreamData(nghttp2_session_get_stream_user_data(session, FrameHdr^.stream_id));

  if not Assigned(StreamData) then
    Exit(0);

  SetString(HeaderName, PAnsiChar(name), namelen);
  SetString(HeaderValue, PAnsiChar(value), valuelen);

  if HeaderName = ':method' then
    StreamData^.Request.Method := UpperCase(HeaderValue)
  else if HeaderName = ':path' then
  begin
    StreamData^.Request.URL := HeaderValue;
    SplitPathQuery(HeaderValue, StreamData^.Request.Path, StreamData^.Request.RawQuery);
  end
  else if HeaderName = ':scheme' then
    { ignore or store }
  else if HeaderName = ':authority' then
    StreamData^.Request.Header.SetValue('Host', HeaderValue)
  else
    StreamData^.Request.Header.SetValue(HeaderName, HeaderValue);

  Result := 0;
end;

// HTTP/2 on_data_chunk_recv callback
function HTTP2OnDataChunkRecvCallback(session: Pnghttp2_session; flags: cuint;
                                      stream_id: nghttp2_stream_id;
                                      const data: PByte; len: csize_t;
                                      user_data: Pointer): cint; cdecl;
var
  StreamData: PHTTP2StreamData;
  Chunk: AnsiString;
begin
  StreamData := PHTTP2StreamData(nghttp2_session_get_stream_user_data(session, stream_id));

  if Assigned(StreamData) then
  begin
    SetString(Chunk, PAnsiChar(data), len);
    StreamData^.Request.Body := StreamData^.Request.Body + string(Chunk);
  end;

  Result := 0;
end;

// HTTP/2 on_stream_close callback
function HTTP2OnStreamCloseCallback(session: Pnghttp2_session; stream_id: nghttp2_stream_id;
                                    error_code: cuint; user_data: Pointer): cint; cdecl;
var
  Conn: PClientConnection;
  StreamData: PHTTP2StreamData;
  Server: THTTPServer;
  Handler: THandlerFunc;
  RedirectTo: string;
  NVA: array[0..1] of Tnghttp2_nv;
  RespBody: string;
begin
  Conn := PClientConnection(user_data);
  StreamData := PHTTP2StreamData(nghttp2_session_get_stream_user_data(session, stream_id));

  if Assigned(StreamData) then
  begin
    WriteLn('HTTP/2 Stream ', stream_id, ' closed: ', StreamData^.Request.Method, ' ', StreamData^.Request.Path);

    Server := Conn^.Server;
    RespBody := 'HTTP/2 Response for ' + StreamData^.Request.Path;

    if Server.FindHandlerByHost(StreamData^.Request.Header.GetValue('Host'), StreamData^.Request.Path, Handler, RedirectTo) then
    begin
       if RedirectTo <> '' then
         RespBody := '301 Moved: ' + RedirectTo
       else
       begin
         // Simple simulation of handler execution for demo
         RespBody := 'Handled by HTTP/2: ' + StreamData^.Request.Path;
       end;
    end
    else
      RespBody := '404 Not Found';

    var StatusVal := '200';
    if RespBody = '404 Not Found' then StatusVal := '404';
    if RespBody.StartsWith('301') then StatusVal := '301';

    NVA[0].name := PByte(':status');
    NVA[0].namelen := 7;
    NVA[0].value := PByte(PAnsiChar(StatusVal));
    NVA[0].valuelen := Length(StatusVal);
    NVA[0].flags := NGHTTP2_NV_FLAG_NONE;

    NVA[1].name := PByte('content-type');
    NVA[1].namelen := 12;
    NVA[1].value := PByte('text/plain');
    NVA[1].valuelen := 10;
    NVA[1].flags := NGHTTP2_NV_FLAG_NONE;

    nghttp2_submit_response(session, stream_id, @NVA[0], 2, nil);

    StreamData^.Request.Free;
    Conn^.HTTP2Streams.Remove(IntToStr(stream_id));
    Dispose(StreamData);
  end;

  Result := 0;
end;
{$ENDIF}

{ --- Utility Functions --- }

function NormalizePath(const Path: string): string;
var
  Parts: TStringArray;
  Stack: array of string;
  I, StackPos: integer;
  Part: string;
begin
  if Path = '' then Exit('/');

  Parts := Path.Split(['/']);
  SetLength(Stack, Length(Parts));
  StackPos := 0;

  for I := 0 to High(Parts) do
  begin
    Part := Parts[I];

    if (Part = '') or (Part = '.') then
      Continue
    else if Part = '..' then
    begin
      if StackPos > 0 then
        Dec(StackPos);
    end
    else
    begin
      Stack[StackPos] := Part;
      Inc(StackPos);
    end;
  end;

  Result := '/';
  for I := 0 to StackPos - 1 do
    Result := Result + Stack[I] + '/';

  if (StackPos > 0) and (Length(Path) > 0) and (Path[Length(Path)] <> '/') then
    SetLength(Result, Length(Result) - 1);

  if Result = '' then Result := '/';
end;

function DecodeURIComponent(const S: string): string;
var
  I: integer;
  Hex: string;
  Code: integer;
begin
  Result := '';
  I := 1;

  while I <= Length(S) do
  begin
    if S[I] = '%' then
    begin
      if I + 2 <= Length(S) then
      begin
        Hex := '$' + Copy(S, I + 1, 2);
        if TryStrToInt(Hex, Code) then
          Result := Result + Chr(Code)
        else
          Result := Result + '%';
        Inc(I, 3);
      end
      else
      begin
        Result := Result + '%';
        Inc(I);
      end;
    end
    else if S[I] = '+' then
    begin
      Result := Result + ' ';
      Inc(I);
    end
    else
    begin
      Result := Result + S[I];
      Inc(I);
    end;
  end;
end;

function SplitPathQuery(const Target: string; out Path, Query: string): boolean;
var
  P, HashPos: SizeInt;
  RawPath: string;
begin
  HashPos := Pos('#', Target);
  if HashPos > 0 then
    RawPath := Copy(Target, 1, HashPos - 1)
  else
    RawPath := Target;

  P := Pos('?', RawPath);
  if P > 0 then
  begin
    Path := Copy(RawPath, 1, P - 1);
    Query := Copy(RawPath, P + 1, MaxInt);
  end
  else
  begin
    Path := RawPath;
    Query := '';
  end;

  Path := DecodeURIComponent(Path);
  Path := NormalizePath(Path);

  Result := True;
end;

function PatternMatch(const Pattern, Path: string): boolean;
var
  NormPattern, NormPath: string;
begin
  NormPattern := NormalizePath(Pattern);
  NormPath := NormalizePath(Path);

  if NormPattern = '/' then Exit(True);

  if (Length(NormPattern) > 0) and (NormPattern[Length(NormPattern)] = '/') then
    Exit(LeftStr(NormPath + '/', Length(NormPattern)) = NormPattern);

  Result := NormPath = NormPattern;
end;

function URLDecode(const S: string): string;
begin
  Result := DecodeURIComponent(S);
end;

function URLEncode(const S: string): string;
const
  Allowed = ['A'..'Z', 'a'..'z', '0'..'9', '-', '_', '.', '~'];
var
  I: integer;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    if S[I] in Allowed then
      Result := Result + S[I]
    else if S[I] = ' ' then
      Result := Result + '+'
    else
      Result := Result + '%' + IntToHex(Ord(S[I]), 2);
  end;
end;

function GetStatusText(Code: integer): string;
begin
  case Code of
    100: Result := 'Continue';
    101: Result := 'Switching Protocols';
    200: Result := 'OK';
    201: Result := 'Created';
    202: Result := 'Accepted';
    204: Result := 'No Content';
    301: Result := 'Moved Permanently';
    302: Result := 'Found';
    304: Result := 'Not Modified';
    400: Result := 'Bad Request';
    401: Result := 'Unauthorized';
    403: Result := 'Forbidden';
    404: Result := 'Not Found';
    405: Result := 'Method Not Allowed';
    413: Result := 'Payload Too Large';
    417: Result := 'Expectation Failed';
    431: Result := 'Request Header Fields Too Large';
    500: Result := 'Internal Server Error';
    501: Result := 'Not Implemented';
    502: Result := 'Bad Gateway';
    503: Result := 'Service Unavailable';
    else
      Result := 'Unknown';
  end;
end;

function FormatHTTPDate: string;
begin
  Result := FormatDateTime('ddd, dd mmm yyyy hh:nn:ss',
    TTimeZone.Local.ToUniversalTime(Now)) + ' GMT';
end;

function WantsKeepAlive(R: TRequest): boolean;
var
  Conn: string;
begin
  Conn := LowerCase(R.Header.GetValue('connection'));
  if R.Proto = 'HTTP/1.1' then
    Result := Conn <> 'close'
  else
    Result := Conn = 'keep-alive';
end;

procedure ServeFile(W: TResponseWriter; R: TRequest; const FilePath: string);
var
  FS: TFileStream;
  Buf: array[0..8191] of byte;
  Count: integer;
  Ext, ContentType: string;
  Chunk: ansistring;
begin
  if not FileExists(FilePath) then
  begin
    W.WriteHeader(404);
    W.Write('File not found');
    Exit;
  end;

  Ext := LowerCase(ExtractFileExt(FilePath));
  case Ext of
    '.html', '.htm': ContentType := 'text/html; charset=utf-8';
    '.css': ContentType := 'text/css';
    '.js': ContentType := 'application/javascript';
    '.json': ContentType := 'application/json';
    '.png': ContentType := 'image/png';
    '.jpg', '.jpeg': ContentType := 'image/jpeg';
    '.gif': ContentType := 'image/gif';
    '.svg': ContentType := 'image/svg+xml';
    '.txt': ContentType := 'text/plain; charset=utf-8';
    '.pdf': ContentType := 'application/pdf';
    '.zip': ContentType := 'application/zip';
    else
      ContentType := 'application/octet-stream';
  end;

  W.Header.SetValue('Content-Type', ContentType);

  try
    FS := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
    try
      W.Header.SetValue('Content-Length', IntToStr(FS.Size));
      W.WriteHeader(200);

      while FS.Position < FS.Size do
      begin
        Count := FS.Read(Buf, SizeOf(Buf));
        if Count > 0 then
        begin
          SetString(Chunk, pansichar(@Buf[0]), Count);
          W.Write(string(Chunk));
        end;
      end;
    finally
      FS.Free;
    end;
  except
    on E: Exception do
    begin
      if not W.HeadersSent then
      begin
        W.WriteHeader(500);
        W.Write('Internal Server Error: ' + E.Message);
      end;
    end;
  end;
end;

function FileServer(const Root: string): THandlerFunc;
begin
  Result := procedure(W: TResponseWriter; R: TRequest)
  var
    RelPath, FullPath: string;
  begin
    if R.Method <> 'GET' then
    begin
      W.WriteHeader(405);
      W.Header.SetValue('Allow', 'GET');
      W.Write('Method Not Allowed');
      Exit;
    end;
    RelPath := StringReplace(R.Path, '/', PathDelim, [rfReplaceAll]);
    if (Pos('..', RelPath) > 0) or (Pos('~', RelPath) > 0) or
    ((Length(RelPath) > 0) and (RelPath[1] = PathDelim)) then
    begin
      W.WriteHeader(403);
      W.Write('Forbidden');
      Exit;
    end;
    FullPath := IncludeTrailingPathDelimiter(Root) + RelPath;
    if DirectoryExists(FullPath) then
      FullPath := IncludeTrailingPathDelimiter(FullPath) + 'index.html';
    ServeFile(W, R, FullPath);
  end;

end;

{ --- TContext --- }

constructor TContext.Create;
begin
  inherited Create;
  FDeadline := 0;
  FCancelled := False;
  FLock := TCriticalSection.Create;
  FValues := TStringList.Create;
end;

destructor TContext.Destroy;
begin
  FValues.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TContext.Cancel;
begin
  FLock.Enter;
  try
    FCancelled := True;
  finally
    FLock.Leave;
  end;
end;

function TContext.IsCancelled: boolean;
begin
  FLock.Enter;
  try
    Result := FCancelled;
  finally
    FLock.Leave;
  end;
end;

procedure TContext.SetDeadline(D: TDateTime);
begin
  FLock.Enter;
  try
    FDeadline := D;
  finally
    FLock.Leave;
  end;
end;

function TContext.IsExpired: boolean;
begin
  FLock.Enter;
  try
    Result := (FDeadline > 0) and (Now > FDeadline);
  finally
    FLock.Leave;
  end;
end;

procedure TContext.SetValue(const Key, Value: string);
begin
  FLock.Enter;
  try
    FValues.Values[Key] := Value;
  finally
    FLock.Leave;
  end;
end;

function TContext.GetValue(const Key: string): string;
begin
  FLock.Enter;
  try
    Result := FValues.Values[Key];
  finally
    FLock.Leave;
  end;
end;

{ --- THeader --- }

constructor THeader.Create;
begin
  inherited Create;
  CaseSensitive := False;
  NameValueSeparator := ':';
  StrictDelimiter := True;
end;

procedure THeader.AddValue(const Key, Value: string);
begin
  Add(Trim(Key) + ': ' + Trim(Value));
end;

procedure THeader.AddRawHeaderLine(const Line: string);
begin
  Add(Trim(Line));
end;

function THeader.GetValue(const Key: string): string;
var
  I, P: integer;
  K, Line: string;
begin
  Result := '';
  K := LowerCase(Trim(Key));
  for I := 0 to Count - 1 do
  begin
    Line := Strings[I];
    P := Pos(':', Line);
    if P <= 0 then Continue;
    if LowerCase(Trim(Copy(Line, 1, P - 1))) = K then
      Exit(Trim(Copy(Line, P + 1, MaxInt)));
  end;
end;

function THeader.GetAllValuesJoined(const Key: string; const Sep: string): string;
var
  I, P: integer;
  K, Line, V: string;
  First: boolean;
begin
  Result := '';
  K := LowerCase(Trim(Key));
  First := True;
  for I := 0 to Count - 1 do
  begin
    Line := Strings[I];
    P := Pos(':', Line);
    if P <= 0 then Continue;
    if LowerCase(Trim(Copy(Line, 1, P - 1))) = K then
    begin
      V := Trim(Copy(Line, P + 1, MaxInt));
      if First then
      begin
        Result := V;
        First := False;
      end
      else
        Result := Result + Sep + V;
    end;
  end;
end;

procedure THeader.SetValue(const Key, Value: string);
var
  I, P: integer;
  K, Line: string;
begin
  K := LowerCase(Trim(Key));
  for I := 0 to Count - 1 do
  begin
    Line := Strings[I];
    P := Pos(':', Line);
    if P <= 0 then Continue;
    if LowerCase(Trim(Copy(Line, 1, P - 1))) = K then
    begin
      Strings[I] := Trim(Key) + ': ' + Trim(Value);
      Exit;
    end;
  end;
  AddValue(Key, Value);
end;

procedure THeader.DeleteKey(const Key: string);
var
  I, P: integer;
  K, Line: string;
begin
  K := LowerCase(Trim(Key));
  for I := Count - 1 downto 0 do
  begin
    Line := Strings[I];
    P := Pos(':', Line);
    if P <= 0 then Continue;
    if LowerCase(Trim(Copy(Line, 1, P - 1))) = K then
      Delete(I);
  end;
end;

{ --- TRequest --- }

constructor TRequest.Create;
begin
  inherited Create;
  Header := THeader.Create;
  Trailer := TTrailer.Create;
  Context := TContext.Create;
  TLS := False;
  ContentLength := -1;
  SetLength(TransferEncoding, 0);
  FCookiesParsed := False;
  FCookies := nil;
end;

destructor TRequest.Destroy;
begin
  if Assigned(FCookies) then FCookies.Free;
  Context.Free;
  Trailer.Free;
  Header.Free;
  inherited Destroy;
end;

function TRequest.HasChunkedEncoding: boolean;
var
  I: integer;
begin
  Result := False;
  for I := 0 to High(TransferEncoding) do
    if LowerCase(TransferEncoding[I]) = 'chunked' then
      Exit(True);
end;

procedure TRequest.ParseQuery(out Params: TStringList);
var
  Pairs: TStringArray;
  I, P: integer;
  Key, Value: string;
begin
  Params := TStringList.Create;
  if RawQuery = '' then Exit;

  Pairs := RawQuery.Split(['&', ';']);
  for I := 0 to High(Pairs) do
  begin
    if Pairs[I] = '' then Continue;
    P := Pos('=', Pairs[I]);
    if P > 0 then
    begin
      Key := URLDecode(Copy(Pairs[I], 1, P - 1));
      Value := URLDecode(Copy(Pairs[I], P + 1, MaxInt));
      Params.Add(Key + '=' + Value);
    end
    else
      Params.Add(URLDecode(Pairs[I]) + '=');
  end;
end;

function TRequest.QueryValue(const Key: string): string;
var
  Params: TStringList;
  I: integer;
begin
  Result := '';
  Params := TStringList.Create;
  try
    ParseQuery(Params);
    I := Params.IndexOfName(Key);
    if I >= 0 then
      Result := Params.ValueFromIndex[I];
  finally
    Params.Free;
  end;
end;

procedure TRequest.ParsePostForm(out Params: TStringList);
var
  CT: string;
  Pairs: TStringArray;
  I, P: integer;
  Key, Value: string;
begin
  Params := TStringList.Create;
  CT := LowerCase(Header.GetValue('content-type'));

  if Pos('application/x-www-form-urlencoded', CT) > 0 then
  begin
    Pairs := Body.Split(['&']);
    for I := 0 to High(Pairs) do
    begin
      if Pairs[I] = '' then Continue;
      P := Pos('=', Pairs[I]);
      if P > 0 then
      begin
        Key := URLDecode(Copy(Pairs[I], 1, P - 1));
        Value := URLDecode(Copy(Pairs[I], P + 1, MaxInt));
        Params.Add(Key + '=' + Value);
      end;
    end;
  end;
end;

function TRequest.PostFormValue(const Key: string): string;
var
  Params: TStringList;
  I: integer;
begin
  Result := '';
  Params := nil;
  try
    ParsePostForm(Params);
    I := Params.IndexOfName(Key);
    if I >= 0 then
      Result := Params.ValueFromIndex[I];
  finally
    Params.Free;
  end;
end;

procedure TRequest.EnsureCookiesParsed;

  procedure ParseCookieHeader(const H: string; Cookies: TStringList);
  var
    I, EqPos: integer;
    Parts: TStringArray;
    Pair, N, V: string;
  begin
    // Cookie: a=b; c=d; e; spaced = ok
    Parts := H.Split([';']);
    for I := 0 to High(Parts) do
    begin
      Pair := Trim(Parts[I]);
      if Pair = '' then Continue;

      EqPos := Pos('=', Pair);
      if EqPos <= 0 then
      begin
        N := Pair;
        V := '';
      end
      else
      begin
        N := Trim(Copy(Pair, 1, EqPos - 1));
        V := Trim(Copy(Pair, EqPos + 1, MaxInt));
      end;

      if (Length(V) >= 2) and (V[1] = '"') and (V[Length(V)] = '"') then
        V := Copy(V, 2, Length(V) - 2);

      if N = '' then Continue;

      Cookies.Values[N] := V;
    end;
  end;

var
  H: string;
begin
  if FCookiesParsed then Exit;
  FCookiesParsed := True;

  if not Assigned(FCookies) then
  begin
    FCookies := TStringList.Create;
    FCookies.NameValueSeparator := '=';
    FCookies.StrictDelimiter := True;
    FCookies.CaseSensitive := False;
  end
  else
    FCookies.Clear;

  // A cookie can be sent in multiple headers
  H := Header.GetAllValuesJoined('cookie', '; ');
  if H <> '' then
    ParseCookieHeader(H, FCookies);
end;

function TRequest.CookieValue(const Name: string): string;
begin
  EnsureCookiesParsed;
  Result := FCookies.Values[Name];
end;

function TRequest.HasCookie(const Name: string): boolean;
begin
  EnsureCookiesParsed;
  Result := FCookies.IndexOfName(Name) >= 0;
end;

procedure TRequest.ParseCookies(out Cookies: TStringList);
begin
  EnsureCookiesParsed;
  Cookies := TStringList.Create;
  Cookies.Assign(FCookies);
end;

{ --- TResponseWriter --- }

constructor TResponseWriter.Create(AConn: PClientConnection; AConnection: string);
begin
  inherited Create;
  FConn := AConn;
  FServer := AConn^.Server;

  FSocket := AConn^.Sock;
  FSSL := AConn^.SSL;
  FUseTLS := AConn^.UseTLS;
  FStatus := 200;
  FHeadersSent := False;
  FTrailersSent := False;
  FConnection := AConnection;
  FChunked := False;
  FHeader := THeader.Create;
  FTrailer := TTrailer.Create;
  FContentLength := 0;
  FExplicitCL := False;
  FBodyBuf := '';
  FBuffered := True;
end;

destructor TResponseWriter.Destroy;
begin
  FTrailer.Free;
  FHeader.Free;
  inherited Destroy;
end;

function TResponseWriter.Header: THeader;
begin
  Result := FHeader;
end;

function TResponseWriter.Trailer: TTrailer;
begin
  Result := FTrailer;
end;

function TResponseWriter.HeadersSent: boolean;
begin
  Result := FHeadersSent;
end;

procedure TResponseWriter.SendRaw(const Buf; Size: integer);
{$IFDEF LINUX}
var
  Ret, Err: Integer;
begin
  if Size <= 0 then Exit;

  if FUseTLS then
  begin
    // Encrypt via SSL_write -> WriteBIO
    Ret := SSLWrite(FSSL, @Buf, Size);
    if Ret <= 0 then
    begin
      Err := SSLGetError(FSSL, Ret);
      if (Err = SSL_ERROR_WANT_WRITE) or (Err = SSL_ERROR_WANT_READ) then
         // In Memory BIO mode, this is rare unless buffer full, handle gracefully
      else
      begin
        LogSSLError('SSL_write failed');
        raise Exception.CreateFmt('SSL_write failed: %d', [Err]);
      end;
    end;
    // Move encrypted data from WriteBIO to OutBuf (for epoll to send)
    FServer.FlushWriteBIOToOutBuf(FConn);
  end
  else
  begin
    // Plain HTTP: append to OutBuf directly
    SetString(AnsiString(FConn^.OutBuf), PAnsiChar(@Buf), Size);
  end;

  // Try to send immediately
  FServer.HandleEpollWrite(FConn);
  // If data remains, enable EPOLLOUT
  if Length(FConn^.OutBuf) > 0 then
    FServer.EnableWriteNotifications(FConn);
end;
{$ELSE}
var
  Ret, Sent: integer;
  P: pbyte;
  SSLErr: integer;
begin
  if Size <= 0 then Exit;

  Sent := 0;
  P := @Buf;

  while Sent < Size do
  begin
    if FUseTLS then
    begin
      // Windows IOCP / Memory BIO
      Ret := SSLWrite(FSSL, P + Sent, Size - Sent);
      if Ret <= 0 then
      begin
        SSLErr := SSLGetError(FSSL, Ret);
        if (SSLErr = SSL_ERROR_WANT_WRITE) or (SSLErr = SSL_ERROR_WANT_READ) then
        begin
          FServer.FlushWriteBIO(FConn); // Try to flush pending
          // In IOCP we wait for completion, but here we might loop or return.
          Continue;
        end;
        LogSSLError('SSL_write failed');
        raise Exception.CreateFmt('SSL_write failed: %d', [SSLErr]);
      end;
    end
    else
    begin
      Ret := SysSend(FSocket, P[Sent], Size - Sent, 0);
      if Ret <= 0 then
        raise Exception.Create('send failed');
    end;
    Inc(Sent, Ret);
  end;
  if FUseTLS then FServer.FlushWriteBIO(FConn);
end;
{$ENDIF}

procedure TResponseWriter.WriteHeader(Code: integer);
begin
  if FHeadersSent then Exit;
  FStatus := Code;
  SendHeadersIfNeeded;
end;

procedure TResponseWriter.SendHeadersIfNeeded;
var
  Headers: string;
  I: integer;
  HasCL: boolean;
  CL: string;
  TrailerNames: string;
begin
  if FHeadersSent then Exit;

  // 101 Switching Protocols: minimal headers only
  if FStatus = 101 then
  begin
    if FHeader.GetValue('Upgrade') = '' then
      raise Exception.Create('101 Switching Protocols requires Upgrade header');

    FStatusText := GetStatusText(FStatus);
    Headers := 'HTTP/1.1 ' + IntToStr(FStatus) + ' ' + FStatusText + #13#10;

    for I := 0 to FHeader.Count - 1 do
      Headers := Headers + Trim(FHeader[I]) + #13#10;

    Headers := Headers + #13#10;
    SendRaw(Headers[1], Length(Headers));
    FHeadersSent := True;
    FConnection := 'upgrade';
    Exit;
  end;

  if FHeader.GetValue('date') = '' then
    FHeader.SetValue('Date', FormatHTTPDate);

  if FHeader.GetValue('connection') = '' then
    FHeader.SetValue('Connection', FConnection);

  if FHeader.GetValue('content-type') = '' then
    FHeader.SetValue('Content-Type', 'text/plain; charset=utf-8');

  CL := FHeader.GetValue('content-length');
  HasCL := CL <> '';

  if HasCL then
  begin
    FChunked := False;
    FExplicitCL := True;
  end
  else
  begin
    FChunked := (LowerCase(FConnection) = 'keep-alive');
    if FChunked then
    begin
      FHeader.SetValue('Transfer-Encoding', 'chunked');

      if FTrailer.Count > 0 then
      begin
        TrailerNames := '';
        for I := 0 to FTrailer.Count - 1 do
        begin
          if I > 0 then TrailerNames := TrailerNames + ', ';
          TrailerNames := TrailerNames + FTrailer.Names[I];
        end;
        if TrailerNames <> '' then
          FHeader.SetValue('Trailer', TrailerNames);
      end;
    end;
  end;

  FStatusText := GetStatusText(FStatus);
  Headers := 'HTTP/1.1 ' + IntToStr(FStatus) + ' ' + FStatusText + #13#10;

  for I := 0 to FHeader.Count - 1 do
    Headers := Headers + Trim(FHeader[I]) + #13#10;

  Headers := Headers + #13#10;

  SendRaw(Headers[1], Length(Headers));
  FHeadersSent := True;
end;

procedure TResponseWriter.SetCookie(const Name, Value: string;
  const Path: string; const Domain: string; Expires: TDateTime;
  MaxAge: integer; Secure: boolean; HttpOnly: boolean; SameSite: TCookieSameSite);

  function CookieDate(const DT: TDateTime): string;
  begin
    // HTTP-date (RFC 7231), GMT
    Result := FormatDateTime('ddd, dd mmm yyyy hh:nn:ss',
      TTimeZone.Local.ToUniversalTime(DT)) + ' GMT';
  end;

  function SameSiteStr(S: TCookieSameSite): string;
  begin
    case S of
      ssLax: Result := 'Lax';
      ssStrict: Result := 'Strict';
      ssNone: Result := 'None';
      else
        Result := '';
    end;
  end;

var
  Line, SS: string;
begin
  if FHeadersSent then
    raise Exception.Create('Cannot set cookie after headers sent');

  if Name = '' then
    raise Exception.Create('Cookie name required');

  // We put Value here as is; if desired, you can URLEncode it from the outside.
  Line := 'Set-Cookie: ' + Name + '=' + Value;

  if Path <> '' then
    Line := Line + '; Path=' + Path;
  if Domain <> '' then
    Line := Line + '; Domain=' + Domain;

  if Expires > 0 then
    Line := Line + '; Expires=' + CookieDate(Expires);

  if MaxAge >= 0 then
    Line := Line + '; Max-Age=' + IntToStr(MaxAge);

  if Secure then
    Line := Line + '; Secure';
  if HttpOnly then
    Line := Line + '; HttpOnly';

  SS := SameSiteStr(SameSite);
  if SS <> '' then
    Line := Line + '; SameSite=' + SS;
  FHeader.AddRawHeaderLine(Line);
end;

procedure TResponseWriter.Write(const S: string);
var
  ChunkHdr: string;
  Ret, Err: Integer;
begin
  if Length(S) = 0 then Exit;

  if FHeadersSent then
  begin
    {$IFDEF WINDOWS}
    if FUseTLS then
    begin
      Ret := SSLWrite(FSSL, @S[1], Length(S));
      if Ret <= 0 then
      begin
        Err := SSLGetError(FSSL, Ret);
        if (Err = SSL_ERROR_WANT_WRITE) then
          FServer.FlushWriteBIO(FConn)
        else
          raise Exception.Create('SSL_write failed');
      end;
      FServer.FlushWriteBIO(FConn);
    end
    else
    {$ENDIF}
    if FChunked then
    begin
      ChunkHdr := IntToHex(Length(S), 1) + #13#10;
      SendRaw(ChunkHdr[1], Length(ChunkHdr));
      SendRaw(S[1], Length(S));
      SendRaw(#13#10, 2);
    end
    else
      SendRaw(S[1], Length(S));
    Exit;
  end;

  if FBuffered then
    FBodyBuf := FBodyBuf + ansistring(S)
  else
  begin
    SendHeadersIfNeeded;
    {$IFDEF WINDOWS}
    if FUseTLS then
    begin
      Ret := SSLWrite(FSSL, @S[1], Length(S));
      if Ret <= 0 then
      begin
        Err := SSLGetError(FSSL, Ret);
        if (Err = SSL_ERROR_WANT_WRITE) then
          FServer.FlushWriteBIO(FConn)
        else
          raise Exception.Create('SSL_write failed');
      end;
      FServer.FlushWriteBIO(FConn);
    end
    else
    {$ENDIF}
    if FChunked then
    begin
      ChunkHdr := IntToHex(Length(S), 1) + #13#10;
      SendRaw(ChunkHdr[1], Length(ChunkHdr));
      SendRaw(S[1], Length(S));
      SendRaw(#13#10, 2);
    end
    else
      SendRaw(S[1], Length(S));
  end;
end;

procedure TResponseWriter.Write(const Buf; Size: integer);
var
  ChunkHdr: string;
  Ret, Err: Integer;
begin
  if Size <= 0 then Exit;

  SendHeadersIfNeeded;

  {$IFDEF WINDOWS}
  if FUseTLS then
  begin
    Ret := SSLWrite(FSSL, @Buf, Size);
    if Ret <= 0 then
    begin
      Err := SSLGetError(FSSL, Ret);
      if (Err = SSL_ERROR_WANT_WRITE) then
        FServer.FlushWriteBIO(FConn)
      else
        raise Exception.Create('SSL_write failed');
    end;
    FServer.FlushWriteBIO(FConn);
  end
  else
  {$ENDIF}
  if FChunked then
  begin
    ChunkHdr := IntToHex(Size, 1) + #13#10;
    SendRaw(ChunkHdr[1], Length(ChunkHdr));
    SendRaw(Buf, Size);
    SendRaw(#13#10, 2);
  end
  else
    SendRaw(Buf, Size);
end;

procedure TResponseWriter.Finish;
var
  EndChunk: string;
  I: integer;
  TrailerData: string;
begin
  // 101 Switching Protocols should not send chunked termination
  if FStatus = 101 then
  begin
    FHeadersSent := True;
    Exit;
  end;

  if (not FHeadersSent) and FBuffered then
  begin
    if (FHeader.GetValue('content-length') = '') and
      (FHeader.GetValue('transfer-encoding') = '') then
      FHeader.SetValue('Content-Length', IntToStr(Length(FBodyBuf)));
  end;

  SendHeadersIfNeeded;

  if FBuffered and (Length(FBodyBuf) > 0) then
  begin
    SendRaw(FBodyBuf[1], Length(FBodyBuf));
    FBodyBuf := '';
  end;

  if FChunked and (not FTrailersSent) then
  begin
    EndChunk := '0' + #13#10;

    if FTrailer.Count > 0 then
    begin
      TrailerData := '';
      for I := 0 to FTrailer.Count - 1 do
        TrailerData := TrailerData + Trim(FTrailer[I]) + #13#10;
      EndChunk := EndChunk + TrailerData;
    end;

    EndChunk := EndChunk + #13#10;
    SendRaw(EndChunk[1], Length(EndChunk));
    FTrailersSent := True;
  end;

  {$IFDEF WINDOWS}
  if FUseTLS then
    FServer.FlushWriteBIO(FConn);
  {$ELSE}
  // ensure all data from WriteBIO is in OutBuf
  if FUseTLS then
    FServer.FlushWriteBIOToOutBuf(FConn);
  {$ENDIF}
end;

{ --- TSSLHandshakeThread --- }

constructor TSSLHandshakeThread.Create(AServer: TObject; AConn: PClientConnection = nil);
begin
  inherited Create(True);
  FServer := AServer;
  {$IFDEF WINDOWS}
  FreeOnTerminate := False;
  {$ELSE}
  FConn := AConn;
  FreeOnTerminate := True;
  {$ENDIF}
end;

procedure TSSLHandshakeThread.Execute;
begin
  // Linux: No longer used. Handshake is handled in epoll loop via ProcessSSL.
  {$IFDEF LINUX}
  NameThreadForDebugging('SSL Handshake Worker (Deprecated)');
  while not Terminated do
    Sleep(100);
  {$ENDIF}
  {$IFDEF WINDOWS}
  // Windows Handshake is handled in IOCP context
  while not Terminated do Sleep(100);
  {$ENDIF}
end;

{ --- THTTPServer --- }

constructor THTTPServer.Create;
begin
  inherited Create;
  FRoutes := TRouteList.Create;
  FHostRoutes := THostRouteList.Create;
  SetLength(FMiddlewares, 0);
  FServerSock := -1;
  FActiveConnections := 0;
  FConnectionsLock := TCriticalSection.Create;
  FSSLCtx := nil;
  FTLSConfig.Enabled := False;
  FConnections := TConnectionList.Create;
  FShutdownEvent := RTLEventCreate;
  FConnectionTimeout := CONNECTION_TIMEOUT;
  FHeaderReadTimeout := HEADER_READ_TIMEOUT;
  FBodyReadTimeout := BODY_READ_TIMEOUT;
  FMaxHeaderBytes := MAX_HEADER_BYTES;
  FMaxBodyBytes := MAX_BODY_BYTES;
  {$IFDEF LINUX}
  FEpollFd := -1;
  FServerIsTLS := False;
  {$ENDIF}
  {$IFDEF WINDOWS}
  FIOCPHandle := 0;
  {$ENDIF}
end;

destructor THTTPServer.Destroy;
begin
  Shutdown;
  RTLeventDestroy(FShutdownEvent);
  CleanupSSL;
  FConnections.Free;
  FRoutes.Free;
  FHostRoutes.Free;
  FConnectionsLock.Free;
  inherited Destroy;
end;

function THTTPServer.InitSSL: boolean;
begin
  Result := False;

  if not SSLInitialized then
  begin
    SSLLoadErrorStrings;
    SSLLibraryInit;
    OpenSSLaddallalgorithms;
    SSLInitialized := True;
  end;

  FSSLCtx := SSLCTXnew(SslTLSMethod);
  if not Assigned(FSSLCtx) then
  begin
    WriteLn('SSL_CTX_new failed');
    Exit;
  end;

  if SslCtxUseCertificateFile(FSSLCtx, pansichar(ansistring(FTLSConfig.CertFile)),
    SSL_FILETYPE_PEM) <= 0 then
  begin
    WriteLn('Failed to load certificate: ', FTLSConfig.CertFile);
    Exit;
  end;

  if SslCtxUsePrivateKeyFile(FSSLCtx, pansichar(ansistring(FTLSConfig.KeyFile)),
    SSL_FILETYPE_PEM) <= 0 then
  begin
    WriteLn('Failed to load private key: ', FTLSConfig.KeyFile);
    Exit;
  end;

  if SslCtxCheckPrivateKeyFile(FSSLCtx) <= 0 then
  begin
    WriteLn('Private key does not match certificate');
    Exit;
  end;

  {$IFDEF ENABLE_HTTP2}
  SSL_CTX_set_alpn_select_cb(FSSLCtx, @ALPNSelectCallback, Self);
  {$ENDIF}

  Result := True;
end;

procedure THTTPServer.CleanupSSL;
begin
  if Assigned(FSSLCtx) then
  begin
    SSLCTXfree(FSSLCtx);
    FSSLCtx := nil;
  end;
end;

{$IFDEF ENABLE_HTTP2}
function THTTPServer.InitHTTP2Session(Conn: PClientConnection): Boolean;
var
  Callbacks: Pnghttp2_session_callbacks;
  Ret: cint;
begin
  Result := False;

  Ret := nghttp2_session_callbacks_new(Callbacks);
  if Ret <> 0 then
  begin
    WriteLn('nghttp2_session_callbacks_new failed: ', nghttp2_strerror(Ret));
    Exit;
  end;

  try
    nghttp2_session_callbacks_set_send_callback(Callbacks, @HTTP2SendCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(Callbacks, @HTTP2OnFrameRecvCallback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(Callbacks, @HTTP2OnBeginHeadersCallback);
    nghttp2_session_callbacks_set_on_header_callback(Callbacks, @HTTP2OnHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(Callbacks, @HTTP2OnDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(Callbacks, @HTTP2OnStreamCloseCallback);

    Ret := nghttp2_session_server_new(Conn^.HTTP2Session, Callbacks^, Conn);
    if Ret <> 0 then
    begin
      WriteLn('nghttp2_session_server_new failed: ', nghttp2_strerror(Ret));
      Exit;
    end;

    Conn^.HTTP2Enabled := True;
    Conn^.HTTP2PrefaceReceived := False;
    Conn^.HTTP2Streams := TFPHashList.Create;

    nghttp2_submit_settings(Conn^.HTTP2Session, nil, 0);

    Result := True;
  finally
    nghttp2_session_callbacks_del(Callbacks);
  end;
end;
{$ENDIF}

procedure THTTPServer.StartSSLHandshake(Conn: PClientConnection);
begin
  // With Memory BIO, handshake is advanced by ProcessSSL called on IO events.
  // We just mark state here.
  Conn^.SSLHandshakeStarted := True;
  Conn^.State := csSSLHandshake;
end;

{$IFDEF LINUX}
procedure THTTPServer.FlushWriteBIOToOutBuf(Conn: PClientConnection);
var
  Tmp: array[0..8191] of Byte;
  N: Integer;
  S: AnsiString;
begin
  if not Conn^.UseTLS then Exit;
  if Conn^.WriteBIO = nil then Exit;

  // Move data from OpenSSL WriteBIO to Connection OutBuf
  while BIOCtrlPending(Conn^.WriteBIO) > 0 do
  begin
    N := BIORead(Conn^.WriteBIO, @Tmp[0], SizeOf(Tmp));
    if N > 0 then
    begin
      SetString(S, PAnsiChar(@Tmp[0]), N);
      Conn^.OutBuf := Conn^.OutBuf + S;
    end
    else
      Break;
  end;

  // If we have data to send, ensure EPOLLOUT is enabled
  if Length(Conn^.OutBuf) > 0 then
    EnableWriteNotifications(Conn);
end;

procedure THTTPServer.ProcessSSL(Conn: PClientConnection);
var
  Ret, Err: Integer;
  Buf: array[0..8191] of Byte;
  ReadLen: Integer;
  Chunk: AnsiString;
  PendingInSSL: Integer;
begin
  if not Conn^.UseTLS then Exit;

  // ===  Handshake  ===
  if not Conn^.HandshakeDone then
  begin
    Ret := SSLAccept(Conn^.SSL);
    if Ret > 0 then
    begin
      Conn^.HandshakeDone := True;
      Conn^.State := csReadingHeaders;
      Conn^.LastActivity := Now;
      Conn^.LastStateChange := Now;

      {$IFDEF ENABLE_HTTP2}
      var const_proto: PByte;
      var proto_len: cuint;
      SSL_get0_alpn_selected(Conn^.SSL, const_proto, proto_len);
      if (proto_len = 2) and (const_proto^ = Ord('h')) and ((const_proto + 1)^ = Ord('2')) then
      begin
        if not InitHTTP2Session(Conn) then
        begin
          CloseConnection(Conn);
          Exit;
        end;
      end;
      {$ENDIF}
    end
    else
    begin
      Err := SSLGetError(Conn^.SSL, Ret);
      case Err of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          ; // Normal, wait for more IO events
        else
        begin
          LogSSLError('SSL_accept');
          CloseConnection(Conn);
          Exit;
        end;
      end;
    end;

    // Flush any data generated by handshake (e.g. ServerHello)
    FlushWriteBIOToOutBuf(Conn);

    // If handshake still pending, exit and wait for next EPOLLIN/EPOLLOUT
    if not Conn^.HandshakeDone then Exit;
  end;

  // Loop to read all available decrypted data from SSL object
  repeat
    PendingInSSL := SSLPending(Conn^.SSL);
    if PendingInSSL > 0 then
      ReadLen := SSLRead(Conn^.SSL, @Buf[0], Min(PendingInSSL, SizeOf(Buf)))
    else
      ReadLen := SSLRead(Conn^.SSL, @Buf[0], SizeOf(Buf));

    if ReadLen > 0 then
    begin
      SetString(Chunk, PAnsiChar(@Buf[0]), ReadLen);
      Conn^.PlainInBuf := Conn^.PlainInBuf + Chunk;
      Conn^.LastActivity := Now;
    end
    else
      Break;
  until False;

  if ReadLen <= 0 then
  begin
    Err := SSLGetError(Conn^.SSL, ReadLen);
    case Err of
      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
        ; // Need more network IO
      SSL_ERROR_ZERO_RETURN:
        begin
          CloseConnection(Conn);
          Exit;
        end;
      else
      begin
        if Err <> SSL_ERROR_SYSCALL then // syscall 0 often means clean shutdown with empty read
          LogSSLError('SSL_read');
        CloseConnection(Conn);
        Exit;
      end;
    end;
  end;

  // === 3. Process HTTP Data ===
  if Length(Conn^.PlainInBuf) > 0 then
    ProcessRequestsFromBuffer(Conn);
end;
{$ENDIF}

{$IFDEF WINDOWS}
procedure THTTPServer.FlushWriteBIO(Conn: PClientConnection);
var
  Pending: size_t;
  Len: Integer;
  WSABuf: TWSABUF;
  Flags: DWORD;
  BytesSent: DWORD;
  Wbio: PBIO;
begin
  if Conn^.WritePending or not Conn^.UseTLS then Exit;

  Wbio := SSLGetWbio(Conn^.SSL);
  if Wbio = nil then Exit;

  Pending := BIOCtrlPending(Wbio);
  if Pending = 0 then Exit;

  if Conn^.WriteIOContext = nil then
    New(Conn^.WriteIOContext);

  FillChar(Conn^.WriteIOContext^.Overlapped, SizeOf(TOverlapped), 0);
  Conn^.WriteIOContext^.Operation := ioWrite;
  Conn^.WriteIOContext^.Connection := Conn;

  Len := BIORead(Wbio, @Conn^.WriteIOContext^.Buffer[0],
                  SizeOf(Conn^.WriteIOContext^.Buffer));
  if Len <= 0 then
  begin
    Dispose(Conn^.WriteIOContext);
    Conn^.WriteIOContext := nil;
    Exit;
  end;

  WSABuf.len := Len;
  WSABuf.buf := @Conn^.WriteIOContext^.Buffer[0];
  Flags := 0;

  if WSASend(TSocket(Conn^.Sock), @WSABuf, 1, BytesSent, Flags,
             @Conn^.WriteIOContext^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError() <> WSA_IO_PENDING then
    begin
      CloseConnection(Conn);
    end;
  end;

  Conn^.WritePending := True;
end;

procedure THTTPServer.ProcessSSL(Conn: PClientConnection);
var
  Ret, Err: Integer;
  Buf: array[0..8191] of Byte;
  ReadLen: Integer;
  Chunk: AnsiString;
  PendingInSSL: Integer;
  HandshakeAdvanced: Boolean;
begin
  if not Conn^.UseTLS then Exit;

  HandshakeAdvanced := False;

  // === Handshake (if still not done) ===
  if not Conn^.HandshakeDone then
  begin
    Ret := SSLAccept(Conn^.SSL);
    if Ret > 0 then
    begin
      Conn^.HandshakeDone := True;
      Conn^.State := csReadingHeaders;
      Conn^.LastActivity := Now;
      Conn^.LastStateChange := Now;

      {$IFDEF ENABLE_HTTP2}
      var const_proto: PByte;
      var proto_len: cuint;
      SSL_get0_alpn_selected(Conn^.SSL, const_proto, proto_len);
      if (proto_len = 2) and (const_proto^ = Ord('h')) and ((const_proto + 1)^ = Ord('2')) then
      begin
        if not InitHTTP2Session(Conn) then
        begin
          CloseConnection(Conn);
          Exit;
        end;
      end;
      {$ENDIF}
      HandshakeAdvanced := True;
    end
    else
    begin
      Err := SSLGetError(Conn^.SSL, Ret);
      case Err of
        SSL_ERROR_WANT_READ:
          ;
        SSL_ERROR_WANT_WRITE:
          FlushWriteBIO(Conn);
        else
        begin
          LogSSLError('SSL_accept');
          CloseConnection(Conn);
          Exit;
        end;
      end;
    end;
    FlushWriteBIO(Conn);
    Exit;
  end;

  // === Reading plaintext ===
  if Conn^.HandshakeDone or HandshakeAdvanced then
  begin
    repeat
      PendingInSSL := SSLPending(Conn^.SSL);
      if PendingInSSL > 0 then
        ReadLen := SSLRead(Conn^.SSL, @Buf[0], Min(PendingInSSL, SizeOf(Buf)))
      else
        ReadLen := SSLRead(Conn^.SSL, @Buf[0], SizeOf(Buf));

      if ReadLen > 0 then
      begin
        SetString(Chunk, PAnsiChar(@Buf[0]), ReadLen);
        Conn^.PlainInBuf := Conn^.PlainInBuf + Chunk;
        Conn^.LastActivity := Now;
      end
      else
        Break;
    until False;

    if ReadLen <= 0 then
    begin
      Err := SSLGetError(Conn^.SSL, ReadLen);
      case Err of
        SSL_ERROR_WANT_READ:
          ;
        SSL_ERROR_WANT_WRITE:
          FlushWriteBIO(Conn);
        SSL_ERROR_ZERO_RETURN,
        SSL_ERROR_SYSCALL:
          CloseConnection(Conn);
        else
        begin
          LogSSLError('SSL_read');
          CloseConnection(Conn);
        end;
      end;
    end;

    if Length(Conn^.PlainInBuf) > 0 then
      ProcessRequestsFromBuffer(Conn);
  end;

  FlushWriteBIO(Conn);
end;
{$ENDIF}

procedure THTTPServer.ProcessRequestsFromBuffer(Conn: PClientConnection);
var
  Head, Body: AnsiString;
  NeedMoreData: Boolean;
  ExpectValue: string;
  I: Integer;
  PendingReq: PPendingRequest;
  ReceivedBodyLen: int64;
  SwitchedToReadingBody: Boolean;
  {$IFDEF ENABLE_HTTP2}
  H2Ret: cint;
  DataPtr: PByte;
  SendLen: cssize_t;
  {$ENDIF}
begin
  SwitchedToReadingBody := False;

  {$IFDEF ENABLE_HTTP2}
  if Conn^.HTTP2Enabled then
  begin
    if (not Conn^.HTTP2PrefaceReceived) and (Length(Conn^.PlainInBuf) >= 24) then
    begin
       if Copy(Conn^.PlainInBuf, 1, 24) = 'PRI * HTTP/2.0'#13#10#13#10'SM'#13#10#13#10 then
       begin
         Delete(Conn^.PlainInBuf, 1, 24);
         if InitHTTP2Session(Conn) then
           Conn^.HTTP2PrefaceReceived := True
         else
           CloseConnection(Conn);
       end;
    end;

    if Conn^.HTTP2Enabled and Conn^.HTTP2PrefaceReceived then
    begin
      H2Ret := nghttp2_session_mem_recv(Conn^.HTTP2Session, @Conn^.PlainInBuf[1], Length(Conn^.PlainInBuf));
      if H2Ret < 0 then
      begin
        CloseConnection(Conn);
        Exit;
      end;
      Delete(Conn^.PlainInBuf, 1, H2Ret);

      // Send responses queued by nghttp2
      repeat
        SendLen := nghttp2_session_mem_send(Conn^.HTTP2Session, DataPtr);
        if SendLen > 0 then
        begin
          if Conn^.UseTLS then
          begin
            SSL_write(Conn^.SSL, DataPtr, SendLen);
            {$IFDEF WINDOWS}
            FlushWriteBIO(Conn);
            {$ELSE}
            FlushWriteBIOToOutBuf(Conn);
            {$ENDIF}
          end
          else
            SysSend(Conn^.Sock, DataPtr^, SendLen, 0);
        end;
      until SendLen <= 0;

      Exit;
    end;
  end;
  {$ENDIF}

  if (Conn^.State = csReadingHeaders) and (Length(Conn^.PlainInBuf) > FMaxHeaderBytes) then
  begin
    WriteLn('Header too large from ', Conn^.Addr);
    SendErrorResponse(Conn, 431, 'Request Header Fields Too Large');
    CloseConnection(Conn);
    Exit;
  end;

  case Conn^.State of
    csReadingHeaders:
    begin
      while TryExtractRequest(Conn^.PlainInBuf, Head, Body, NeedMoreData) do
      begin
        New(PendingReq);
        PendingReq^.Head := Head;
        PendingReq^.Body := Body;
        Conn^.PipelineRequests.Add(PendingReq);
      end;

      if Conn^.PipelineRequests.Count > 0 then
      begin
        for I := 0 to Conn^.PipelineRequests.Count - 1 do
        begin
          PendingReq := PPendingRequest(Conn^.PipelineRequests[I]);

          ParseRequestLine(PendingReq^.Head, Conn^.Addr, Conn^.UseTLS, Conn^.CurrentRequest);
          Conn^.KeepAlive := WantsKeepAlive(Conn^.CurrentRequest);

          ExpectValue := LowerCase(Conn^.CurrentRequest.Header.GetValue('expect'));
          if ExpectValue = '100-continue' then
          begin
            Conn^.ExpectingContinue := True;
            SendContinueResponse(Conn);
          end;

          if Conn^.CurrentRequest.HasChunkedEncoding and (Conn^.CurrentRequest.ContentLength >= 0) then
            Conn^.CurrentRequest.ContentLength := -1;

          if Conn^.CurrentRequest.ContentLength > FMaxBodyBytes then
          begin
            WriteLn('Body too large from ', Conn^.Addr, ': ', Conn^.CurrentRequest.ContentLength);
            SendErrorResponse(Conn, 413, 'Payload Too Large');
            CloseConnection(Conn);
            Dispose(PendingReq);
            Exit;
          end;

          Conn^.CurrentRequest.Body := string(PendingReq^.Body);

          if (Conn^.CurrentRequest.ContentLength > 0) and (not Conn^.CurrentRequest.HasChunkedEncoding) then
          begin
            ReceivedBodyLen := Length(PendingReq^.Body);

            if ReceivedBodyLen < Conn^.CurrentRequest.ContentLength then
            begin
              Conn^.BodyBytesRemaining := Conn^.CurrentRequest.ContentLength - ReceivedBodyLen;
              Conn^.State := csReadingBody;
              Conn^.BodyBytesRead := ReceivedBodyLen;

              Dispose(PendingReq);
              Conn^.PipelineRequests.Delete(I);
              SwitchedToReadingBody := True;
              Break;
            end;
          end;

          if Conn^.CurrentRequest.HasChunkedEncoding then
          begin
            Conn^.State := csReadingChunks;
            Conn^.ChunkBytesRemaining := 0;
            if not ReadChunkedBody(Conn) then
            begin
              Dispose(PendingReq);
              Break;
            end;
            ProcessRequest(Conn);
            Conn^.State := csReadingHeaders;
          end
          else
          begin
            ProcessRequest(Conn);
            Conn^.State := csReadingHeaders;
          end;

          Dispose(PendingReq);

          if not Conn^.KeepAlive then
            Break;
        end;

        if not SwitchedToReadingBody then
          Conn^.PipelineRequests.Clear;
      end;
    end;

    csReadingBody:
    begin
      if Conn^.BodyBytesRead > FMaxBodyBytes then
      begin
        WriteLn('Body too large from ', Conn^.Addr);
        SendErrorResponse(Conn, 413, 'Payload Too Large');
        CloseConnection(Conn);
        Exit;
      end;

      if Length(Conn^.PlainInBuf) >= Conn^.BodyBytesRemaining then
      begin
        Conn^.CurrentRequest.Body := Conn^.CurrentRequest.Body +
          string(Copy(Conn^.PlainInBuf, 1, Conn^.BodyBytesRemaining));
        Delete(Conn^.PlainInBuf, 1, Conn^.BodyBytesRemaining);

        Inc(Conn^.BodyBytesRead, Conn^.BodyBytesRemaining);

        ProcessRequest(Conn);
        Conn^.State := csReadingHeaders;
        Conn^.BodyBytesRead := 0;

        if Length(Conn^.PlainInBuf) > 0 then
          ProcessRequestsFromBuffer(Conn);
      end
      else
      begin
        Conn^.CurrentRequest.Body := Conn^.CurrentRequest.Body + string(Conn^.PlainInBuf);

        Inc(Conn^.BodyBytesRead, Length(Conn^.PlainInBuf));

        Conn^.BodyBytesRemaining := Conn^.BodyBytesRemaining - Length(Conn^.PlainInBuf);
        Conn^.PlainInBuf := '';
      end;
    end;

    csReadingChunks:
    begin
      if ReadChunkedBody(Conn) then
      begin
        ProcessRequest(Conn);
        Conn^.State := csReadingHeaders;

        if Length(Conn^.PlainInBuf) > 0 then
          ProcessRequestsFromBuffer(Conn);
      end;
    end;
  end;
end;

{$IFDEF LINUX}
procedure THTTPServer.InitEpoll;
begin
  FEpollFd := epoll_create(1024);
  if FEpollFd < 0 then
    raise Exception.Create('epoll_create failed');
end;

procedure THTTPServer.AddToEpoll(Sock: Integer; Conn: PClientConnection);
var
  Event: epoll_event;
begin
  FillChar(Event, SizeOf(Event), 0);
  Event.events := EPOLLIN or EPOLLET;
  Event.data.ptr := Conn;

  if epoll_ctl(FEpollFd, EPOLL_CTL_ADD, Sock, @Event) < 0 then
    WriteLn('epoll_ctl ADD failed for socket ', Sock);
end;

procedure THTTPServer.ModEpoll(Sock: Integer; Conn: PClientConnection; Events: Cardinal);
var
  E: epoll_event;
begin
  FillChar(E, SizeOf(E), 0);
  E.events := Events or EPOLLET;
  E.data.ptr := Conn;
  if epoll_ctl(FEpollFd, EPOLL_CTL_MOD, Sock, @E) < 0 then
    WriteLn('epoll_ctl MOD failed for socket ', Sock, ' errno=', fpgeterrno);
end;

procedure THTTPServer.EnableWriteNotifications(Conn: PClientConnection);
begin
  ModEpoll(Conn^.Sock, Conn, EPOLLIN or EPOLLOUT);
end;

procedure THTTPServer.DisableWriteNotifications(Conn: PClientConnection);
begin
  ModEpoll(Conn^.Sock, Conn, EPOLLIN);
end;

procedure THTTPServer.HandleEpollWrite(Conn: PClientConnection);
var
  Ret: Integer;
begin
  if Conn^.State = csClosed then Exit;
  if Length(Conn^.OutBuf) = 0 then
  begin
    DisableWriteNotifications(Conn);
    Exit;
  end;

  while Length(Conn^.OutBuf) > 0 do
  begin
    // Just send whatever is in OutBuf. For TLS it's encrypted, for HTTP it's plain.
    Ret := SysSend(Conn^.Sock, Conn^.OutBuf[1], Length(Conn^.OutBuf), 0);
    if Ret > 0 then
      Delete(Conn^.OutBuf, 1, Ret)
    else
    begin
      if (fpgeterrno = ESysEAGAIN) or (fpgeterrno = ESysEWOULDBLOCK) then
        Break;
      CloseConnection(Conn);
      Exit;
    end;
  end;

  if Length(Conn^.OutBuf) = 0 then
    DisableWriteNotifications(Conn)
  else
    EnableWriteNotifications(Conn);
end;

procedure THTTPServer.RemoveFromEpoll(Sock: Integer);
begin
  epoll_ctl(FEpollFd, EPOLL_CTL_DEL, Sock, nil);
end;

procedure THTTPServer.HandleEpollRead(Conn: PClientConnection);
var
  Buf: array[0..4095] of Byte;
  Count: Integer;
  Chunk: AnsiString;
  ReadTmp: AnsiString;
  ReadAny: Boolean;
begin
  ReadTmp := '';
  ReadAny := False;

  // Timeout logic is handled in RunEpollLoop

  try
    if Conn^.UseTLS then
    begin
      // === TLS Mode ===
      // Read ENCRYPTED data from Socket
      repeat
        Count := SysRecv(Conn^.Sock, @Buf[0], SizeOf(Buf), 0);
        if Count > 0 then
        begin
          // Feed encrypted data to ReadBIO
          BIOWrite(Conn^.ReadBIO, @Buf[0], Count);
          ReadAny := True;
        end
        else if Count = 0 then
        begin
          CloseConnection(Conn);
          Exit;
        end
        else
        begin
          if (fpgeterrno = ESysEAGAIN) or (fpgeterrno = ESysEWOULDBLOCK) then
            Break;
          CloseConnection(Conn);
          Exit;
        end;
      until False;

      // If we fed data, process SSL (Handshake or Decrypt)
      if ReadAny then
      begin
        Conn^.LastActivity := Now;
        ProcessSSL(Conn);
      end;
    end
    else
    begin
      // === Plain HTTP Mode ===
      repeat
        Count := SysRecv(Conn^.Sock, @Buf[0], SizeOf(Buf), 0);
        if Count > 0 then
        begin
          SetString(Chunk, PAnsiChar(@Buf[0]), Count);
          ReadTmp := ReadTmp + Chunk;
          ReadAny := True;
        end
        else if Count = 0 then
        begin
          CloseConnection(Conn);
          Exit;
        end
        else
        begin
          if (fpgeterrno = ESysEAGAIN) or (fpgeterrno = ESysEWOULDBLOCK) then
            Break;
          CloseConnection(Conn);
          Exit;
        end;
      until False;

      if ReadAny then
      begin
        Conn^.PlainInBuf := Conn^.PlainInBuf + ReadTmp;
        Conn^.LastActivity := Now;
        ProcessRequestsFromBuffer(Conn);
      end;
    end;
  except
    on E: Exception do
    begin
      WriteLn('Connection error: ', E.Message);
      CloseConnection(Conn);
    end;
  end;
end;

procedure THTTPServer.RunEpollLoop;
var
  Events: array[0..63] of epoll_event;
  NumEvents, I: Integer;
  Conn: PClientConnection;
  LastTimeoutCheck: TDateTime;
  ClientSock, Len: Integer;
  ClientAddr: TSockAddrIn;
  ClientAddrStr: string;
begin
  LastTimeoutCheck := Now;

  while not ShutdownRequested do
  begin
    NumEvents := epoll_wait(FEpollFd, @Events[0], Length(Events), 100);

    if SecondsBetween(Now, LastTimeoutCheck) >= 1 then
    begin
      CheckConnectionTimeouts;
      LastTimeoutCheck := Now;
    end;

    if NumEvents < 0 then
    begin
      if ShutdownRequested then Break;
      Continue;
    end;

    for I := 0 to NumEvents - 1 do
    begin
      if Events[I].data.fd = FServerSock then
      begin
        // ====== Accept New Connections ======
        repeat
          Len := SizeOf(ClientAddr);
          ClientSock := SysAccept(FServerSock, ClientAddr, Len);

          if ClientSock = -1 then
          begin
             if (fpgeterrno = ESysEAGAIN) or (fpgeterrno = ESysEWOULDBLOCK) then
               Break;
             Continue;
          end;

          SysSetNonBlocking(ClientSock, True);

          ClientAddrStr := NetAddrToStr(ClientAddr.sin_addr) + ':' + IntToStr(ntohs(ClientAddr.sin_port));

          New(Conn);
          Conn^.Sock := ClientSock;
          Conn^.Addr := ClientAddrStr;
          Conn^.PlainInBuf := '';
          Conn^.OutBuf := '';
          Conn^.CurrentRequest := nil;
          Conn^.CurrentWriter := nil;
          Conn^.KeepAlive := True;
          Conn^.PipelineRequests := TList.Create;
          Conn^.LastActivity := Now;
          Conn^.LastStateChange := Now;
          Conn^.ChunkBytesRemaining := 0;
          Conn^.BodyBytesRemaining := 0;
          Conn^.ExpectingContinue := False;
          Conn^.HeaderBytesRead := 0;
          Conn^.BodyBytesRead := 0;
          Conn^.SSLHandshakeStarted := False;
          Conn^.HeaderStartTime := Now;
          Conn^.Server := Self;

          {$IFDEF ENABLE_HTTP2}
          Conn^.HTTP2Session := nil;
          Conn^.HTTP2Enabled := False;
          Conn^.HTTP2PrefaceReceived := False;
          Conn^.HTTP2Streams := nil;
          {$ENDIF}

          // Memory BIO Init (Common with Windows logic now)
          if FServerIsTLS then
          begin
            Conn^.SSL := SSLNew(FSSLCtx);
            Conn^.UseTLS := True;
            Conn^.ReadBIO := BIONew(BioSMem());
            Conn^.WriteBIO := BIONew(BioSMem());
            SSLSetBio(Conn^.SSL, Conn^.ReadBIO, Conn^.WriteBIO);
            SSLSetAcceptState(Conn^.SSL);
            Conn^.HandshakeDone := False;
            Conn^.State := csSSLHandshake;
            // No TSSLHandshakeThread started here
          end
          else
          begin
            Conn^.SSL := nil;
            Conn^.UseTLS := False;
            Conn^.State := csReadingHeaders;
          end;

          FConnections.Add(Conn);
          IncConnections;
          AddToEpoll(ClientSock, Conn);
        until False;
      end
      else
      begin
        // ====== Client Event ======
        Conn := PClientConnection(Events[I].data.ptr);

        if (Events[I].events and (EPOLLERR or EPOLLHUP)) <> 0 then
        begin
          CloseConnection(Conn);
          Continue;
        end;

        if (Events[I].events and EPOLLIN) <> 0 then
          HandleEpollRead(Conn);

        if (Events[I].events and EPOLLOUT) <> 0 then
          HandleEpollWrite(Conn);
      end;
    end;
  end;
end;
{$ENDIF}

{$IFDEF MSWINDOWS}

procedure THTTPServer.InitIOCP;
begin
  FIOCPHandle := CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
  if FIOCPHandle = 0 then
    raise Exception.Create('CreateIoCompletionPort failed');
end;

procedure THTTPServer.AssociateWithIOCP(Sock: TSocket; Conn: PClientConnection);
begin
  if CreateIoCompletionPort(Sock, FIOCPHandle, ULONG_PTR(Conn), 0) = 0 then
    raise Exception.Create('Failed to associate socket with IOCP');
end;

procedure THTTPServer.PostRead(Conn: PClientConnection);
var
  IOCtx: PIOContext;
  Flags: DWORD;
  BytesRecv: DWORD;
  WSABuf: TWSABUF;
begin
  New(IOCtx);
  FillChar(IOCtx^.Overlapped, SizeOf(TOverlapped), 0);
  IOCtx^.Operation := ioRead;
  IOCtx^.Connection := Conn;
  Conn^.IOContext := IOCtx;

  WSABuf.len := SizeOf(IOCtx^.Buffer);
  WSABuf.buf := @IOCtx^.Buffer[0];
  Flags := 0;

  if WSARecv(Conn^.Sock, @WSABuf, 1, BytesRecv, Flags, @IOCtx^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError <> WSA_IO_PENDING then
    begin
      if Conn^.IOContext = IOCtx then
         Conn^.IOContext := nil;
      Dispose(IOCtx);
      CloseConnection(Conn);
    end;
  end;
end;

procedure THTTPServer.RunIOCPLoop;
var
  BytesTransferred: DWORD;
  CompletionKey: ULONG_PTR;
  Overlapped: POverlapped;
  IOCtx: PIOContext;
  Conn: PClientConnection;
  Chunk: AnsiString;
  LastTimeoutCheck: TDateTime;
begin
  LastTimeoutCheck := Now;

  while not ShutdownRequested do
  begin
    if not GetQueuedCompletionStatus(FIOCPHandle, BytesTransferred,
                                     CompletionKey, Overlapped, 100) then
    begin
      if Overlapped <> nil then
      begin
        IOCtx := PIOContext(Overlapped);
        CloseConnection(IOCtx^.Connection);
        Dispose(IOCtx);
      end;

      if SecondsBetween(Now, LastTimeoutCheck) >= 1 then
      begin
        CheckConnectionTimeouts;
        LastTimeoutCheck := Now;
      end;

      Continue;
    end;

    if Overlapped = nil then
    begin
      if SecondsBetween(Now, LastTimeoutCheck) >= 1 then
      begin
        CheckConnectionTimeouts;
        LastTimeoutCheck := Now;
      end;
      Continue;
    end;

    IOCtx := PIOContext(Overlapped);
    Conn := IOCtx^.Connection;

    try
      case IOCtx^.Operation of
        ioRead:
        begin
          if BytesTransferred = 0 then
          begin
            CloseConnection(Conn);
            Dispose(IOCtx);
            Continue;
          end;

          if Conn^.UseTLS then
          begin
            BIOWrite(Conn^.ReadBIO, @IOCtx^.Buffer[0], BytesTransferred);
            ProcessSSL(Conn);
          end
          else
          begin
            SetString(Chunk, PAnsiChar(@IOCtx^.Buffer[0]), BytesTransferred);
            Conn^.PlainInBuf := Conn^.PlainInBuf + Chunk;
            Conn^.LastActivity := Now;
            ProcessRequestsFromBuffer(Conn);
          end;

          Dispose(IOCtx);
          PostRead(Conn);
        end;

        ioWrite:
        begin
          Conn^.WritePending := False;
          if Assigned(Conn^.WriteIOContext) then
          begin
            Dispose(Conn^.WriteIOContext);
            Conn^.WriteIOContext := nil;
          end;
          if Conn^.UseTLS then
            ProcessSSL(Conn);
        end;
      end;

    except
      on E: Exception do
      begin
        WriteLn('IOCP error: ', E.Message);
        CloseConnection(Conn);
        if Conn^.IOContext = IOCtx then
           Conn^.IOContext := nil;
        Dispose(IOCtx);
      end;
    end;
  end;
end;
{$ENDIF}

procedure THTTPServer.CheckConnectionTimeouts;
var
  I: integer;
  Conn: PClientConnection;
  Timeout: integer;
begin
  FConnectionsLock.Enter;
  try
    for I := FConnections.Count - 1 downto 0 do
    begin
      Conn := PClientConnection(FConnections[I]);
      if not Assigned(Conn) then Continue;

      case Conn^.State of
        csSSLHandshake, csReadingHeaders:
          Timeout := FHeaderReadTimeout;
        csReadingBody, csReadingChunks:
          Timeout := FBodyReadTimeout;
        else
          Timeout := FConnectionTimeout;
      end;

      if SecondsBetween(Now, Conn^.LastActivity) > Timeout then
      begin
        WriteLn('Closing idle connection: ', Conn^.Addr);
        CloseConnection(Conn);
      end;
    end;
  finally
    FConnectionsLock.Leave;
  end;
end;

procedure THTTPServer.Use(Middleware: TMiddleware);
begin
  SetLength(FMiddlewares, Length(FMiddlewares) + 1);
  FMiddlewares[High(FMiddlewares)] := Middleware;
end;

procedure THTTPServer.HandleFunc(const Pattern: string; Handler: THandlerFunc);
var
  Route: TRoute;
  I: integer;
  Wrapped: THandlerFunc;
begin
  Wrapped := Handler;
  for I := High(FMiddlewares) downto 0 do
    Wrapped := FMiddlewares[I](Wrapped);

  Route.Pattern := Pattern;
  Route.Handler := Wrapped;
  FRoutes.Add(Route);
end;

procedure THTTPServer.HandleFuncHost(const Host, Pattern: string; Handler: THandlerFunc);
var
  Route: THostRoute;
  I: integer;
  Wrapped: THandlerFunc;
begin
  Wrapped := Handler;
  for I := High(FMiddlewares) downto 0 do
    Wrapped := FMiddlewares[I](Wrapped);

  Route.Host := LowerCase(Host);
  Route.Pattern := Pattern;
  Route.Handler := Wrapped;
  FHostRoutes.Add(Route);
end;

function THTTPServer.FindHandlerByHost(const Host, Path: string;
  out Handler: THandlerFunc; out RedirectTo: string): boolean;
var
  I: integer;
  ReqHost: string;
  HostPort: TStringArray;
begin
  Result := False;
  RedirectTo := '';

  ReqHost := LowerCase(Host);
  HostPort := ReqHost.Split([':']);
  if Length(HostPort) > 0 then
    ReqHost := HostPort[0];

  for I := 0 to FHostRoutes.Count - 1 do
  begin
    if (FHostRoutes[I].Host = ReqHost) and PatternMatch(
      FHostRoutes[I].Pattern, Path) then
    begin
      Handler := FHostRoutes[I].Handler;
      Exit(True);
    end;
  end;

  Result := FindHandlerOrRedirect(Path, Handler, RedirectTo);
end;

function THTTPServer.FindHandlerOrRedirect(const Path: string;
  out Handler: THandlerFunc; out RedirectTo: string): boolean;
var
  I: integer;
  BestIdx: integer;
  BestLen: integer;
  P: string;
  IsSubtree, BestIsSubtree: boolean;
begin
  Result := False;
  BestIdx := -1;
  BestLen := -1;
  RedirectTo := '';

  for I := 0 to FRoutes.Count - 1 do
  begin
    P := FRoutes[I].Pattern;
    if PatternMatch(P, Path) then
    begin
      IsSubtree := (Length(P) > 0) and (P[Length(P)] = '/');
      if BestIdx >= 0 then
        BestIsSubtree := (Length(FRoutes[BestIdx].Pattern) > 0) and
          (FRoutes[BestIdx].Pattern[Length(FRoutes[BestIdx].Pattern)] = '/')
      else
        BestIsSubtree := False;

      if (Length(P) > BestLen) or ((Length(P) = BestLen) and
        BestIsSubtree and (not IsSubtree)) then
      begin
        BestLen := Length(P);
        BestIdx := I;
      end;
    end;
  end;

  if BestIdx >= 0 then
  begin
    Handler := FRoutes[BestIdx].Handler;
    Result := True;
    Exit;
  end;

  if (Length(Path) > 0) and (Path[Length(Path)] <> '/') then
  begin
    for I := 0 to FRoutes.Count - 1 do
    begin
      P := FRoutes[I].Pattern;
      if (P = Path + '/') then
      begin
        RedirectTo := Path + '/';
        Exit(True);
      end;
    end;
  end;
end;

function ExtractContentLength(const Head: ansistring): int64;
var
  S, Line: string;
  SL: TStringList;
  I, P: integer;
begin
  Result := -1;
  SL := TStringList.Create;
  try
    S := StringReplace(string(Head), #13#10, #10, [rfReplaceAll]);
    SL.Text := S;
    for I := 0 to SL.Count - 1 do
    begin
      Line := SL[I];
      if (Length(Line) >= 15) and (LowerCase(Copy(Line, 1, 15)) = 'content-length') then
      begin
        P := Pos(':', Line);
        if P > 0 then
          Exit(StrToInt64Def(Trim(Copy(Line, P + 1, MaxInt)), -1));
      end;
    end;
  finally
    SL.Free;
  end;
end;

procedure THTTPServer.ParseRequestLine(const Head: ansistring;
  const ClientAddr: string; UseTLS: boolean; out R: TRequest);
var
  I, J: integer;
  Line, Key, Value: string;
  Lines: TStringList;
  TE, CL: string;
  TEParts, Parts: TStringArray;
  K: integer;
begin
  if Assigned(R) then
    FreeAndNil(R);
  R := TRequest.Create;
  R.RemoteAddr := ClientAddr;
  R.TLS := UseTLS;

  Lines := TStringList.Create;
  try
    Lines.Text := StringReplace(string(Head), #13#10, #10, [rfReplaceAll]);

    if Lines.Count > 0 then
    begin
      Line := Lines[0];
      Parts := Line.Split([' ']);
      if Length(Parts) >= 3 then
      begin
        R.Method := UpperCase(Parts[0]);
        R.URL := Parts[1];
        SplitPathQuery(R.URL, R.Path, R.RawQuery);
        R.Proto := Parts[2];
      end;
    end;

    for I := 1 to Lines.Count - 1 do
    begin
      Line := Trim(Lines[I]);
      if Line = '' then Break;
      J := Pos(':', Line);
      if J > 0 then
      begin
        Key := Trim(Copy(Line, 1, J - 1));
        Value := Trim(Copy(Line, J + 1, MaxInt));
        R.Header.AddValue(Key, Value);
      end;
    end;

    TE := R.Header.GetValue('transfer-encoding');
    if TE <> '' then
    begin
      TEParts := TE.Split([',']);
      SetLength(R.TransferEncoding, Length(TEParts));
      for K := 0 to High(TEParts) do
        R.TransferEncoding[K] := Trim(TEParts[K]);
    end;

    CL := R.Header.GetValue('content-length');
    if CL <> '' then
      R.ContentLength := StrToInt64Def(CL, -1)
    else
      R.ContentLength := -1;

  finally
    Lines.Free;
  end;
end;

function THTTPServer.TryExtractRequest(var InBuf: ansistring;
  out Head, Body: ansistring; out NeedMoreData: boolean): boolean;
var
  P: SizeInt;
  HeadRaw: ansistring;
  Lines: TStringList;
  I, J: integer;
  Line, Key, Value: string;
  CL: int64;
  HasCL: boolean;
  TE: string;
  IsChunked: boolean;
begin
  Result := False;
  Head := '';
  Body := '';
  NeedMoreData := False;

  // find end of headers
  P := Pos(#13#10#13#10, InBuf);
  if P = 0 then
  begin
    NeedMoreData := True;
    Exit(False);
  end;

  // Get headers with the divider
  HeadRaw := Copy(InBuf, 1, P + 3);

  // Parse of Content-Length & Transfer-Encoding
  CL := -1;
  HasCL := False;
  IsChunked := False;

  Lines := TStringList.Create;
  try
    Lines.Text := StringReplace(string(HeadRaw), #13#10, #10, [rfReplaceAll]);

    for I := 1 to Lines.Count - 1 do
    begin
      Line := Trim(Lines[I]);
      if Line = '' then Break;

      J := Pos(':', Line);
      if J <= 0 then Continue;

      Key := LowerCase(Trim(Copy(Line, 1, J - 1)));
      Value := Trim(Copy(Line, J + 1, MaxInt));

      if Key = 'content-length' then
      begin
        CL := StrToInt64Def(Value, -1);
        HasCL := (CL >= 0);
      end
      else if Key = 'transfer-encoding' then
      begin
        TE := LowerCase(Value);
        if Pos('chunked', TE) > 0 then
          IsChunked := True;
      end;
    end;
  finally
    Lines.Free;
  end;

  // Chunked encoding
  if IsChunked then
  begin
    Head := HeadRaw;
    Body := '';
    Delete(InBuf, 1, P + 3);
    Result := True;
    Exit;
  end;

  // Doesn't have Content-Length or it equal 0
  if (not HasCL) or (CL = 0) then
  begin
    Head := HeadRaw;
    Body := '';
    Delete(InBuf, 1, P + 3);
    Result := True;
    Exit;
  end;

  // Have Content-Length > 0
  if Length(InBuf) < (P + 3 + CL) then
  begin
    NeedMoreData := True;
    Exit(False);
  end;

  Head := HeadRaw;
  Body := Copy(InBuf, P + 4, CL);
  Delete(InBuf, 1, P + 3 + CL);
  Result := True;
end;

function THTTPServer.ReadChunkedBody(Conn: PClientConnection): boolean;
var
  P: SizeInt;
  ChunkSizeLine: string;
  ChunkSize: int64;
  ChunkData: ansistring;
  TrailerLine: string;
  ColonPos: integer;
  TotalBodySize: int64;
begin
  Result := False;
  TotalBodySize := Length(Conn^.CurrentRequest.Body);

  while True do
  begin
    if Conn^.ChunkBytesRemaining = 0 then
    begin
      P := Pos(#13#10, Conn^.PlainInBuf);
      if P = 0 then Exit(False);

      ChunkSizeLine := Trim(string(Copy(Conn^.PlainInBuf, 1, P - 1)));
      Delete(Conn^.PlainInBuf, 1, P + 1);

      P := Pos(';', ChunkSizeLine);
      if P > 0 then
        ChunkSizeLine := Copy(ChunkSizeLine, 1, P - 1);

      ChunkSize := StrToInt64Def('$' + ChunkSizeLine, -1);
      if ChunkSize < 0 then
        raise Exception.Create('Invalid chunk size');

      if ChunkSize > MAX_CHUNK_SIZE then
        raise Exception.Create('Chunk too large');

      if ChunkSize = 0 then
      begin
        while True do
        begin
          P := Pos(#13#10, Conn^.PlainInBuf);
          if P = 0 then Exit(False);

          TrailerLine := Trim(string(Copy(Conn^.PlainInBuf, 1, P - 1)));
          Delete(Conn^.PlainInBuf, 1, P + 1);

          if TrailerLine = '' then Break;

          ColonPos := Pos(':', TrailerLine);
          if ColonPos > 0 then
          begin
            Conn^.CurrentRequest.Trailer.AddValue(
              Trim(Copy(TrailerLine, 1, ColonPos - 1)),
              Trim(Copy(TrailerLine, ColonPos + 1, MaxInt))
              );
          end;
        end;

        Exit(True);
      end;

      Conn^.ChunkBytesRemaining := ChunkSize;
    end;

    if Length(Conn^.PlainInBuf) < Conn^.ChunkBytesRemaining then
      Exit(False);

    ChunkData := Copy(Conn^.PlainInBuf, 1, Conn^.ChunkBytesRemaining);
    Delete(Conn^.PlainInBuf, 1, Conn^.ChunkBytesRemaining);

    TotalBodySize := TotalBodySize + Conn^.ChunkBytesRemaining;
    if TotalBodySize > FMaxBodyBytes then
      raise Exception.Create('Body too large');

    Conn^.CurrentRequest.Body := Conn^.CurrentRequest.Body + string(ChunkData);
    Conn^.ChunkBytesRemaining := 0;

    if Length(Conn^.PlainInBuf) < 2 then
      Exit(False);
    Delete(Conn^.PlainInBuf, 1, 2);
  end;
end;

procedure THTTPServer.SendContinueResponse(Conn: PClientConnection);
var
  Response: ansistring;
begin
  Response := 'HTTP/1.1 100 Continue'#13#10#13#10;

  {$IFDEF WINDOWS}
  if Conn^.UseTLS then
  begin
    SSLWrite(Conn^.SSL, @Response[1], Length(Response));
    FlushWriteBIO(Conn);
  end
  else
  {$ENDIF}
  if Conn^.UseTLS and Assigned(Conn^.SSL) then
  begin
    SSLWrite(Conn^.SSL, @Response[1], Length(Response));
    {$IFDEF LINUX}
    FlushWriteBIOToOutBuf(Conn);
    {$ELSE}
    FlushWriteBIO(Conn);
    {$ENDIF}
  end
  else if Conn^.Sock >= 0 then
    SysSend(Conn^.Sock, Response[1], Length(Response), 0);

  Conn^.ExpectingContinue := False;
end;

procedure THTTPServer.SendErrorResponse(Conn: PClientConnection;
  Code: integer; const Msg: string);
var
  Response: string;
  Body: string;
begin
  Body := IntToStr(Code) + ' ' + Msg;

  Response := 'HTTP/1.1 ' + IntToStr(Code) + ' ' + Msg + #13#10;
  Response := Response + 'Content-Type: text/plain'#13#10;
  Response := Response + 'Content-Length: ' + IntToStr(Length(Body)) + #13#10;
  Response := Response + 'Connection: close'#13#10;
  Response := Response + #13#10;
  Response := Response + Body;

  if Conn^.UseTLS and Assigned(Conn^.SSL) then
  begin
    SSLWrite(Conn^.SSL, @Response[1], Length(Response));
    {$IFDEF LINUX}
    FlushWriteBIOToOutBuf(Conn);
    {$ELSE}
    FlushWriteBIO(Conn);
    {$ENDIF}
  end
  else if Conn^.Sock >= 0 then
    SysSend(Conn^.Sock, Response[1], Length(Response), 0);

  Conn^.KeepAlive := False;
end;

procedure THTTPServer.ProcessRequest(Conn: PClientConnection);
var
  Handler: THandlerFunc;
  RedirectTo: string;
  Host: string;
begin
  Conn^.CurrentRequest.Context.SetDeadline(IncSecond(Now, 30));

  if ShutdownRequested then
  begin
    Conn^.KeepAlive := False;
    if Assigned(Conn^.CurrentWriter) then
    begin
      Conn^.CurrentWriter.WriteHeader(503);
      Conn^.CurrentWriter.Write('Server is shutting down');
      Conn^.CurrentWriter.Finish;
    end;
    CloseConnection(Conn);
    Exit;
  end;

  Host := Conn^.CurrentRequest.Header.GetValue('Host');
  Conn^.CurrentRequest.Context.SetValue('Host', Host);

  Conn^.CurrentWriter := TResponseWriter.Create(
    Conn, IfThen(Conn^.KeepAlive, 'keep-alive', 'close'));

  try
    if FindHandlerByHost(Host, Conn^.CurrentRequest.Path, Handler, RedirectTo) then
    begin
      if RedirectTo <> '' then
      begin
        Conn^.CurrentWriter.Header.SetValue('Location', RedirectTo);
        Conn^.CurrentWriter.WriteHeader(301);
        Conn^.CurrentWriter.Write('Moved Permanently');
      end
      else
      begin
        try
          Handler(Conn^.CurrentWriter, Conn^.CurrentRequest);
        except
          on E: Exception do
          begin
            if not Conn^.CurrentWriter.HeadersSent then
            begin
              Conn^.CurrentWriter.WriteHeader(500);
              Conn^.CurrentWriter.Write('Internal Server Error: ' + E.Message);
            end;
            WriteLn('Handler error: ', E.Message);
          end;
        end;
      end;
    end
    else
    begin
      Conn^.CurrentWriter.WriteHeader(404);
      Conn^.CurrentWriter.Write('404 Not Found');
    end;

    Conn^.CurrentWriter.Finish;
  finally
    FreeAndNil(Conn^.CurrentWriter);
    FreeAndNil(Conn^.CurrentRequest);
  end;

  Conn^.State := csReadingHeaders;
  Conn^.HeaderStartTime := Now;
  Conn^.LastActivity := Now;
  Conn^.BodyBytesRead := 0;

  {$IFDEF LINUX}
  if (Length(Conn^.PlainInBuf) > 0) and Conn^.KeepAlive then
    HandleEpollRead(Conn);
  {$ENDIF}
end;

procedure THTTPServer.CloseConnection(Conn: PClientConnection);
var
  I: integer;
  PendingReq: PPendingRequest;
  {$IFDEF ENABLE_HTTP2}
  StreamData: PHTTP2StreamData;
  {$ENDIF}
begin
  if Conn^.State = csClosed then Exit;

  {$IFDEF LINUX}
  if FEpollFd >= 0 then
    RemoveFromEpoll(Conn^.Sock);
  {$ENDIF}

  {$IFDEF ENABLE_HTTP2}
  if Conn^.HTTP2Enabled then
  begin
    if Assigned(Conn^.HTTP2Session) then
    begin
      nghttp2_session_del(Conn^.HTTP2Session);
      Conn^.HTTP2Session := nil;
    end;

    if Assigned(Conn^.HTTP2Streams) then
    begin
      for I := 0 to Conn^.HTTP2Streams.Count - 1 do
      begin
        StreamData := PHTTP2StreamData(Conn^.HTTP2Streams[I]);
        if Assigned(StreamData) then
        begin
          StreamData^.Request.Free;
          Dispose(StreamData);
        end;
      end;
      FreeAndNil(Conn^.HTTP2Streams);
    end;
  end;
  {$ENDIF}

  if Conn^.UseTLS and Assigned(Conn^.SSL) then
  begin
    SSLShutdown(Conn^.SSL);
    SSLFree(Conn^.SSL);
    Conn^.SSL := nil;
    // BIOs are freed by SSL_free
  end;

  if Conn^.Sock >= 0 then
  begin
    SysClose(Conn^.Sock);
    Conn^.Sock := -1;
  end;

  if Assigned(Conn^.CurrentRequest) then
    FreeAndNil(Conn^.CurrentRequest);

  if Assigned(Conn^.CurrentWriter) then
    FreeAndNil(Conn^.CurrentWriter);

  if Assigned(Conn^.PipelineRequests) then
  begin
    for I := 0 to Conn^.PipelineRequests.Count - 1 do
    begin
      PendingReq := PPendingRequest(Conn^.PipelineRequests[I]);
      Dispose(PendingReq);
      Conn^.PipelineRequests[I] := nil;
    end;
    Conn^.PipelineRequests.Clear;
    FreeAndNil(Conn^.PipelineRequests);
  end;

  Conn^.State := csClosed;

  {$IFDEF WINDOWS}
  Conn^.IOContext := nil;
  {$ENDIF}

  FConnections.Remove(Conn);
  Dispose(Conn);
  DecConnections;
end;

procedure THTTPServer.IncConnections;
begin
  FConnectionsLock.Enter;
  try
    Inc(FActiveConnections);
  finally
    FConnectionsLock.Leave;
  end;
end;

procedure THTTPServer.DecConnections;
begin
  FConnectionsLock.Enter;
  try
    Dec(FActiveConnections);
  finally
    FConnectionsLock.Leave;
  end;
end;

function THTTPServer.ActiveConnections: integer;
begin
  FConnectionsLock.Enter;
  try
    Result := FActiveConnections;
  finally
    FConnectionsLock.Leave;
  end;
end;

procedure THTTPServer.WaitForConnections;
var
  StartTime: TDateTime;
  TimeoutReached: boolean;
  I: integer;
  Conn: PClientConnection;
begin
  StartTime := Now;
  WriteLn('Graceful shutdown: waiting for ', ActiveConnections, ' connections...');

  while ActiveConnections > 0 do
  begin
    TimeoutReached := SecondsBetween(Now, StartTime) >= FConnectionTimeout;

    if TimeoutReached then
    begin
      WriteLn('Shutdown timeout reached, forcing close of ',
        ActiveConnections, ' connections');

      FConnectionsLock.Enter;
      try
        for I := FConnections.Count - 1 downto 0 do
        begin
          Conn := PClientConnection(FConnections[I]);
          if Assigned(Conn) then
            CloseConnection(Conn);
        end;
      finally
        FConnectionsLock.Leave;
      end;
      Break;
    end;

    Sleep(100);
  end;

  WriteLn('All connections closed');
end;

procedure THTTPServer.Shutdown;
begin
  if ShutdownRequested then Exit;

  WriteLn('Initiating graceful shutdown...');
  ShutdownRequested := True;
  RTLeventSetEvent(FShutdownEvent);

  if FServerSock >= 0 then
  begin
    {$IFDEF LINUX}
    if FEpollFd >= 0 then
      RemoveFromEpoll(FServerSock);
    {$ENDIF}
    SysClose(FServerSock);
    FServerSock := -1;
  end;

  WaitForConnections;

  {$IFDEF LINUX}
  if FEpollFd >= 0 then
  begin
    fpclose(FEpollFd);
    FEpollFd := -1;
  end;
  {$ENDIF}

  {$IFDEF WINDOWS}
  if FIOCPHandle <> 0 then
  begin
    CloseHandle(FIOCPHandle);
    FIOCPHandle := 0;
  end;
  {$ENDIF}
end;

{$IFDEF UNIX}
procedure HandleSignal(Sig: cint); cdecl;
begin
  if (Sig = SIGINT) or (Sig = SIGTERM) then
  begin
    WriteLn(#13#10'Shutdown signal received...');
    ShutdownRequested := True;
  end;
end;
{$ENDIF}

procedure THTTPServer.ListenAndServe(const Addr: string);
var
  ClientSock: integer;
  Sin, ClientAddr: TSockAddrIn;
  Sin6: sockaddr_in6;
  Len: integer;
  Port: word;
  OptVal: integer;
  ClientAddrStr: string;
  Conn: PClientConnection;
  UseIPv6: boolean;
  {$IFDEF LINUX}
  Event: epoll_event;
  {$ENDIF}
  {$IFDEF WINDOWS}
  TV: TTimeVal;
  FDS: TFDSet;
  IOCPThread: TThread;
  {$ENDIF}
begin
  {$IFDEF UNIX}
  fpSignal(SIGINT, @HandleSignal);
  fpSignal(SIGTERM, @HandleSignal);
  {$ENDIF}

  if (Length(Addr) = 0) or (Addr[1] <> ':') then
    raise Exception.Create('Invalid address format, use :port');
  Port := StrToInt(Copy(Addr, 2, MaxInt));

  UseIPv6 := False;

  {$IFDEF WINDOWS}
  if UseIPv6 then
    FServerSock := socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
  else
    FServerSock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  {$ELSE}
  if UseIPv6 then
    FServerSock := fpsocket(AF_INET6, SOCK_STREAM, 0)
  else
    FServerSock := fpsocket(AF_INET, SOCK_STREAM, 0);
  {$ENDIF}

  if FServerSock = -1 then
    raise Exception.Create('Socket creation failed');

  OptVal := 1;
  {$IFDEF WINDOWS}
  setsockopt(TSocket(FServerSock), SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));
  {$ELSE}
  fpsetsockopt(FServerSock, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));
  {$ENDIF}

  if UseIPv6 then
  begin
    FillChar(Sin6, SizeOf(Sin6), 0);
    Sin6.sin6_family := AF_INET6;
    Sin6.sin6_port := htons(Port);

    {$IFDEF WINDOWS}
    if bind(TSocket(FServerSock), PSockAddr(@Sin6), SizeOf(Sin6)) = SOCKET_ERROR then
      raise Exception.Create('Bind failed');
    {$ELSE}
    if fpbind(FServerSock, @Sin6, SizeOf(Sin6)) = -1 then
      raise Exception.Create('Bind failed');
    {$ENDIF}
  end
  else
  begin
    FillChar(Sin, SizeOf(Sin), 0);
    Sin.sin_family := AF_INET;
    Sin.sin_port := htons(Port);
    Sin.sin_addr.s_addr := INADDR_ANY;

    {$IFDEF WINDOWS}
    if bind(TSocket(FServerSock), PSockAddr(@Sin), SizeOf(Sin)) = SOCKET_ERROR then
      raise Exception.Create('Bind failed');
    {$ELSE}
    if fpbind(FServerSock, @Sin, SizeOf(Sin)) = -1 then
      raise Exception.Create('Bind failed');
    {$ENDIF}
  end;

  {$IFDEF WINDOWS}
  if listen(TSocket(FServerSock), SOMAXCONN) = SOCKET_ERROR then
    raise Exception.Create('Listen failed');
  {$ELSE}
  if fplisten(FServerSock, 128) = -1 then
    raise Exception.Create('Listen failed');
  {$ENDIF}

  WriteLn('HTTP server listening on http://localhost:', Port);
  WriteLn('Press Ctrl+C to stop');

  {$IFDEF LINUX}
  FServerIsTLS := False;
  InitEpoll;
  SysSetNonBlocking(FServerSock, True);

  FillChar(Event, SizeOf(Event), 0);
  Event.events := EPOLLIN;
  Event.data.fd := FServerSock;

  if epoll_ctl(FEpollFd, EPOLL_CTL_ADD, FServerSock, @Event) < 0 then
    raise Exception.Create('Failed to add listen socket to epoll');

  RunEpollLoop;
  {$ENDIF}

  {$IFDEF WINDOWS}
  InitIOCP;

  IOCPThread := TIOCPLoopThread.Create(Self);

  try
    while not ShutdownRequested do
    begin

      FD_ZERO(FDS);
      _FD_SET(TSocket(FServerSock), FDS);
      TV.tv_sec := 0;
      TV.tv_usec := 100000;

      if select(0, @FDS, nil, nil, @TV) > 0 then
      begin
        Len := SizeOf(ClientAddr);
        ClientSock := SysAccept(FServerSock, ClientAddr, Len);

        if ClientSock <> -1 then
        begin
          ClientAddrStr := string(inet_ntoa(ClientAddr.sin_addr)) + ':' +
                           IntToStr(ntohs(ClientAddr.sin_port));

          New(Conn);
          Conn^.Sock := ClientSock;
          Conn^.SSL := nil;
          Conn^.UseTLS := False;
          Conn^.Addr := ClientAddrStr;
          Conn^.State := csReadingHeaders;
          Conn^.PlainInBuf := '';
          Conn^.OutBuf := '';
          Conn^.CurrentRequest := nil;
          Conn^.CurrentWriter := nil;
          Conn^.KeepAlive := True;
          Conn^.PipelineRequests := TList.Create;
          Conn^.LastActivity := Now;
          Conn^.LastStateChange := Now;
          Conn^.ChunkBytesRemaining := 0;
          Conn^.BodyBytesRemaining := 0;
          Conn^.ExpectingContinue := False;
          Conn^.HeaderBytesRead := 0;
          Conn^.BodyBytesRead := 0;
          Conn^.SSLHandshakeStarted := False;
          Conn^.IOContext := nil;
          Conn^.HeaderStartTime := Now;
          Conn^.Server := Self;

          {$IFDEF ENABLE_HTTP2}
          Conn^.HTTP2Session := nil;
          Conn^.HTTP2Enabled := False;
          Conn^.HTTP2PrefaceReceived := False;
          Conn^.HTTP2Streams := nil;
          {$ENDIF}

          FConnections.Add(Conn);
          IncConnections;
          SysSetNonBlocking(ClientSock, True);
          AssociateWithIOCP(TSocket(ClientSock), Conn);

          PostRead(Conn);
        end;
      end;
    end;
  finally
    ShutdownRequested := True;
    IOCPThread.WaitFor;
    IOCPThread.Free;
  end;
  {$ENDIF}

  Shutdown;
  WriteLn('Server stopped gracefully');
end;

procedure THTTPServer.ListenAndServeTLS(const Addr: string;
  const CertFile, KeyFile: string);
var
  ClientSock: integer;
  Sin, ClientAddr: TSockAddrIn;
  Sin6: sockaddr_in6;
  Len: integer;
  Port: word;
  OptVal: integer;
  ClientAddrStr: string;
  Conn: PClientConnection;
  UseIPv6: boolean;
  {$IFDEF LINUX}
  Event: epoll_event;
  {$ENDIF}
  {$IFDEF WINDOWS}
  TV: TTimeVal;
  FDS: TFDSet;
  IOCPThread: TIOCPLoopThread;
  {$ENDIF}
begin
  {$IFDEF UNIX}
  fpSignal(SIGINT, @HandleSignal);
  fpSignal(SIGTERM, @HandleSignal);
  {$ENDIF}

  FTLSConfig.Enabled := True;
  FTLSConfig.CertFile := CertFile;
  FTLSConfig.KeyFile := KeyFile;

  if not InitSSL then
    raise Exception.Create('Failed to initialize SSL');

  if (Length(Addr) = 0) or (Addr[1] <> ':') then
    raise Exception.Create('Invalid address format, use :port');
  Port := StrToInt(Copy(Addr, 2, MaxInt));

  UseIPv6 := False;

  {$IFDEF WINDOWS}
  if UseIPv6 then
    FServerSock := socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
  else
    FServerSock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  {$ELSE}
  if UseIPv6 then
    FServerSock := fpsocket(AF_INET6, SOCK_STREAM, 0)
  else
    FServerSock := fpsocket(AF_INET, SOCK_STREAM, 0);
  {$ENDIF}

  if FServerSock = -1 then
    raise Exception.Create('Socket creation failed');

  OptVal := 1;
  {$IFDEF WINDOWS}
  setsockopt(TSocket(FServerSock), SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));
  {$ELSE}
  fpsetsockopt(FServerSock, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal));
  {$ENDIF}

  if UseIPv6 then
  begin
    FillChar(Sin6, SizeOf(Sin6), 0);
    Sin6.sin6_family := AF_INET6;
    Sin6.sin6_port := htons(Port);

    {$IFDEF WINDOWS}
    if bind(TSocket(FServerSock), PSockAddr(@Sin6), SizeOf(Sin6)) = SOCKET_ERROR then
      raise Exception.Create('Bind failed');
    {$ELSE}
    if fpbind(FServerSock, @Sin6, SizeOf(Sin6)) = -1 then
      raise Exception.Create('Bind failed');
    {$ENDIF}
  end
  else
  begin
    FillChar(Sin, SizeOf(Sin), 0);
    Sin.sin_family := AF_INET;
    Sin.sin_port := htons(Port);
    Sin.sin_addr.s_addr := INADDR_ANY;

    {$IFDEF WINDOWS}
    if bind(TSocket(FServerSock), PSockAddr(@Sin), SizeOf(Sin)) = SOCKET_ERROR then
      raise Exception.Create('Bind failed');
    {$ELSE}
    if fpbind(FServerSock, @Sin, SizeOf(Sin)) = -1 then
      raise Exception.Create('Bind failed');
    {$ENDIF}
  end;

  {$IFDEF WINDOWS}
  if listen(TSocket(FServerSock), SOMAXCONN) = SOCKET_ERROR then
    raise Exception.Create('Listen failed');
  {$ELSE}
  if fplisten(FServerSock, 128) = -1 then
    raise Exception.Create('Listen failed');
  {$ENDIF}

  WriteLn('HTTPS server listening on https://localhost:', Port);
  WriteLn('Press Ctrl+C to stop');

  {$IFDEF LINUX}
  FServerIsTLS := True;
  InitEpoll;
  SysSetNonBlocking(FServerSock, True);

  FillChar(Event, SizeOf(Event), 0);
  Event.events := EPOLLIN;
  Event.data.fd := FServerSock;

  if epoll_ctl(FEpollFd, EPOLL_CTL_ADD, FServerSock, @Event) < 0 then
    raise Exception.Create('Failed to add TLS listen socket to epoll');

  RunEpollLoop;
  {$ENDIF}

  {$IFDEF WINDOWS}
  InitIOCP;

  IOCPThread := TIOCPLoopThread.Create(Self);
  try
    while not ShutdownRequested do
    begin
      FD_ZERO(FDS);
      _FD_SET(TSocket(FServerSock), FDS);
      TV.tv_sec := 0;
      TV.tv_usec := 100000;

      if select(0, @FDS, nil, nil, @TV) > 0 then
      begin
        Len := SizeOf(ClientAddr);
        ClientSock := SysAccept(FServerSock, ClientAddr, Len);

        if ClientSock <> -1 then
        begin
          ClientAddrStr := string(inet_ntoa(ClientAddr.sin_addr)) + ':' +
                           IntToStr(ntohs(ClientAddr.sin_port));

          New(Conn);
          Conn^.Sock := ClientSock;
          Conn^.SSL := SSLNew(FSSLCtx);
          if Conn^.SSL = nil then
          begin
            SysClose(ClientSock);
            Dispose(Conn);
            Continue;
          end;

          Conn^.ReadBIO := BIONew(BioSMem());
          Conn^.WriteBIO := BIONew(BioSMem());
          if (Conn^.ReadBIO = nil) or (Conn^.WriteBIO = nil) then
          begin
            SSLFree(Conn^.SSL);
            SysClose(ClientSock);
            Dispose(Conn);
            Continue;
          end;

          SSLSetBio(Conn^.SSL, Conn^.ReadBIO, Conn^.WriteBIO);
          SSLSetAcceptState(Conn^.SSL);
          Conn^.HandshakeDone := False;

          Conn^.UseTLS := True;
          Conn^.Addr := ClientAddrStr;
          Conn^.State := csSSLHandshake;
          Conn^.PlainInBuf := '';
          Conn^.OutBuf := '';
          Conn^.CurrentRequest := nil;
          Conn^.CurrentWriter := nil;
          Conn^.KeepAlive := True;
          Conn^.PipelineRequests := TList.Create;
          Conn^.LastActivity := Now;
          Conn^.LastStateChange := Now;
          Conn^.ChunkBytesRemaining := 0;
          Conn^.BodyBytesRemaining := 0;
          Conn^.ExpectingContinue := False;
          Conn^.HeaderBytesRead := 0;
          Conn^.BodyBytesRead := 0;
          Conn^.SSLHandshakeStarted := False;
          Conn^.IOContext := nil;
          Conn^.WritePending := False;
          Conn^.WriteIOContext := nil;
          Conn^.HeaderStartTime := Now;
          Conn^.Server := Self;

          {$IFDEF ENABLE_HTTP2}
          Conn^.HTTP2Session := nil;
          Conn^.HTTP2Enabled := False;
          Conn^.HTTP2PrefaceReceived := False;
          Conn^.HTTP2Streams := nil;
          {$ENDIF}

          FConnections.Add(Conn);
          IncConnections;
          SysSetNonBlocking(ClientSock, True);
          AssociateWithIOCP(TSocket(ClientSock), Conn);

          PostRead(Conn);
        end;
      end;
    end;
    finally
      ShutdownRequested := True;
      IOCPThread.WaitFor;
      IOCPThread.Free;
     end;
  {$ENDIF}

  Shutdown;
  WriteLn('Server stopped gracefully');
end;

end.
