**AdvancedHTTPServer** — lightweight high-performance HTTP/1.1 server written in **Free Pascal**  
(inspired by Go's `net/http` package philosophy)

The main goal of this library is to provide **simple, pleasant and familiar API** for creating HTTP servers in Pascal, close in spirit to the minimalistic and productive approach of Go's standard library.

### Main design principles

- Minimal boilerplate
- Handler-first approach (`THandlerFunc = reference to procedure(W: TResponseWriter; R: TRequest)`)
- Middleware support (exactly like in Go)
- Clean separation of concerns
- Good performance out of the box (epoll on Linux / IOCP on Windows)
- TLS support (including HTTP/2 in future versions — currently exists but not production ready)
- Keep-alive & HTTP pipelining support

### Quick Start Examples

```pascal
// Minimal "Hello World" server
procedure HelloHandler(w: TResponseWriter; r: TRequest);
begin
  w.Write('Hello, ' + r.RemoteAddr + '!');
end;

var srv: THTTPServer;
begin
  srv := THTTPServer.Create;
  try
    srv.HandleFunc('/', @HelloHandler);
    srv.ListenAndServe(':8080');
  finally
    srv.Free;
  end;
end;
```

### Routing styles comparison

```pascal
// 1. Simple global routes (most common style)
srv.HandleFunc('/',          HomeHandler);
srv.HandleFunc('/about',     AboutHandler);
srv.HandleFunc('/api/users', UsersAPIHandler);

// 2. With host matching (virtual hosts)
srv.HandleHostFunc('api.example.com', '/users', UsersAPIHandler);
srv.HandleHostFunc('blog.example.com', '/',     BlogHandler);

// 3. Using path prefix (more manual, but possible)
srv.HandleFunc('/static/', StaticFilesHandler);
```

### Middleware (very similar to Go style)

```pascal
function LoggingMiddleware(next: THandlerFunc): THandlerFunc;
begin
  Result := procedure(w: TResponseWriter; r: TRequest)
  var start: TDateTime;
  begin
    start := Now;
    WriteLn('→ ', r.Method, ' ', r.URL);
    next(w, r);
    WriteLn('← ', w.Status, ' in ', MilliSecondsBetween(Now, start), 'ms');
  end;
end;

function AuthMiddleware(next: THandlerFunc): THandlerFunc;
begin
  Result := procedure(w: TResponseWriter; r: TRequest)
  begin
    if not IsAuthenticated(r) then
    begin
      w.WriteHeader(401);
      w.Write('Unauthorized');
      Exit;
    end;
    next(w, r);
  end;
end;

// Usage
srv.Use(@LoggingMiddleware);
srv.Use(@RecoveryMiddleware);  // panic → 500
srv.Use(@AuthMiddleware);      // applies only to following routes

srv.HandleFunc('/profile', ProfileHandler);     // protected
srv.HandleFunc('/public',  PublicPageHandler);  // not protected!
```

Using recovery middleware with router(AdvancedHTTPRecovery.pas)
```pascal
var
  S: THTTPServer;
  R: THTTPRouter;
  Rec: THTTPRecovery;
begin
  Randomize;

  S := THTTPServer.Create;
  R := THTTPRouter.Create(S);
  Rec := THTTPRecovery.Create;
  try
    Rec.ExposeExceptionMessage := False;
    Rec.PreferJSON := True;

    //This is router level
    R.Use(Rec.RouterMiddleware);

    // Routes...
    // R.GET('/ping', [ ... ]);

    R.Mount;
    S.ListenAndServe('0.0.0.0:8080');
  finally
    Rec.Free;
    R.Free;
    S.Free;
  end;
end;
```
Using recovery middleware with server without router:
```pascal
uses
  AdvancedHTTPServer, AdvancedHTTPRecovery;

var
  S: THTTPServer;
  Rec: THTTPRecovery;
begin
  Randomize;

  S := THTTPServer.Create;
  Rec := THTTPRecovery.Create;
  try
    Rec.ExposeExceptionMessage := False; // production
    Rec.AddRequestID := True;
    S.Use(Rec.Middleware);

    // Next routes / router.Mount etc.
    // S.ListenAndServe('0.0.0.0:8080');
  finally
    Rec.Free;
    S.Free;
  end;
end.;
```
Using CORS middleware:

```pascal
var
  Cfg: TCorsConfig;
begin
  Cfg := CorsDefaultConfig;
  Cfg.AllowAnyOrigin := False;
  Cfg.AllowedOrigins := TStringArray.Create(
    'https://*.example.com',
    'http://localhost:*'
  );
  Cfg.AllowCredentials := True;

  Router.Use(CorsMiddleware(Router, Cfg));
end;
```

### Trailers

Send HTTP trailers (like gRPC):

```pascal
W.Trailer.AddValue('X-Checksum', 'abc123');
W.WriteHeader(200);
W.Write('data...');
W.Finish; // sends trailers
```

### Chunked Encoding

Write streaming responses:

```pascal
W.WriteHeader(200);
for i := 1 to 5 do
begin
  W.Write('Chunk ' + IntToStr(i));
  Sleep(100);
end;
W.Finish;
```


### Current patterns 

```pascal
// 1. Classic REST + JSON API
procedure TasksAPI(w: TResponseWriter; r: TRequest);
begin
  case r.Method of
    'GET':    ServeTaskList(w, r);
    'POST':   CreateTask(w, r);
    'PUT':    UpdateTask(w, r);
    'DELETE': DeleteTask(w, r);
  else
    w.WriteHeader(405);
    w.Header.SetValue('Allow', 'GET, POST, PUT, DELETE');
  end;
end;

// 2. SPA + API on same server (very popular nowadays)
srv.HandleFunc('/api/',    apiRouter);
srv.HandleFunc('/',        ServeSPAIndex);   // returns index.html for all other paths

// 3. API Versioning (several popular styles)
srv.HandleFunc('/api/v1/tasks', v1.TasksHandler);
srv.HandleFunc('/api/v2/tasks', v2.TasksHandler);

// or (more clean for many versions)

var apiV1 := srv.Group('/api/v1');
apiV1.Use(@ApiVersionMiddleware('v1'));
apiV1.HandleFunc('/tasks', TasksV1);
apiV1.HandleFunc('/users', UsersV1);
```

### Feature matrix (2026) 

| Feature                          | Status               | Notes                                          |
|:---------------------------------|:--------------------:|:-----------------------------------------------|
| HTTP/1.1 Keep-Alive              | ✓                    | good support                                   |
| HTTP Pipelining                  | ✓                    | supported but rarely used nowadays             |
| HTTPS/TLS                        | ✓                    | OpenSSL                                        |
| HTTP/2                           | ⚠ partial / optional | nghttp2 support exists but not production ready|
| epoll (Linux)                    | ✓                    | high performance                               |
| IOCP (Windows)                   | ✓                    | good performance                               |
| Middleware chain                 | ✓                    | very similar to Go                             |
| Request Context (per-request)    | ✓                    | `TRequest.Context`                             |
| ResponseWriter buffering         | ✓                    | automatic chunking when needed                 |
| Cookies                          | ✓                    | convenient `SetCookie` & `CookieValue`         |
| Query & Form parsing             | ✓                    | `QueryValue`, `PostFormValue`                  |
| JSON handling                    | —                    | use fpjson / other libraries                   |
| Graceful shutdown                | partial              | basic support exists                           |
| Request body size limit          | ✓                    | configurable                                   |
| Route groups / subrouters        | ✓                    | Implemented in AdvancedHTTPRouter              |
| URL parameters / :id style       | ✓                    | Implemented in AdvancedHTTPRouter              |

### Dependencies

- **Free Pascal Compiler** 3.2+ (with anonymous function support)
- **OpenSSL** (for TLS)
- *(Optional)* **nghttp2** (for HTTP/2)

### Performance

| Feature | Implementation |
|--------|----------------|
| **Linux** | `epoll` + edge-triggered I/O |
| **Windows** | IOCP + Memory BIO for TLS |
| **Concurrency** | Single-threaded event loop (no locks on hot path) |
| **Memory** | Reuse buffers, minimal allocations |

> **Note**: Like Go, it’s **not multi-core by default**. For more cores, run multiple instances behind a load balancer.

###Security

- **Path normalization** — blocks `..` and `%2e%2e`
- **Header/body limits** — prevents slowloris and memory exhaustion
- **Secure cookies** — `HttpOnly`, `Secure`, `SameSite`
- **Graceful shutdown** — no dropped requests
- **TLS 1.2+** — with modern cipher suites

### Recommended architecture 

To determine the recommended project architecture, we recommend reviewing the sample catalog. Samples include implementations of simple authorization, a one-time note service, a private notepad, and several others. A project structure in the style of golang like this:

```text
project/
├── main.lpr                 ← run created server with ListenAndServe\ListenAndServeTLS
├── server/
│   ├── server.pas           ← creates & configures THTTPServer
│   ├── middleware.pas
│   ├── handlers/
│   │   ├── auth.pas
│   │   ├── tasks.pas
│   │   ├── users.pas
│   │   └── static.pas
│   └── router.pas           ← simple path dispatching logic
├── models/
│   └── task.pas
├── storage/
│   └── sqlite_tasks.pas
└── frontend/                ← SPA / static files
    ├── index.html
    ├── assets/
    └── ...
```
> **Note**: Please note that the examples compile and run on Windows and Linux, but working with TLS requires OpenSSL for Windows or LibSSL for Linux. To work with examples using sqlite, you need sqlite.


### Minimal useful skeleton 

```pascal
program ahttpservdemo;

{$mode objfpc}{$H+}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes,
  SysUtils,
  CustApp,
  AdvancedHTTPServer,
  DateUtils;

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
      Next(W, R);  

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

  procedure RootHandler(W: TResponseWriter; R: TRequest);
  var
    i: integer;
    proto: string;
  begin
    W.Header.SetValue('Content-Type', 'text/html; charset=utf-8');

    if R.HasChunkedEncoding then
      W.Trailer.AddValue('X-Request-ID', '12345');

    W.Write('<html><body>');
    W.Write('<h1>Welcome to Advanced FreePascal HTTP Server</h1>');
    if R.TLS then
      Proto := 'HTTPS'
    else
      Proto := 'HTTP';
    W.Write('<p>Protocol: ' + Proto + '</p>');
    W.Write('<p>Method: ' + R.Method + '</p>');
    W.Write('<p>Path: ' + R.Path + '</p>');
    W.Write('<p>Chunked: ' + BoolToStr(R.HasChunkedEncoding, True) + '</p>');

    if R.Trailer.Count > 0 then
    begin
      W.Write('<h2>Request Trailers:</h2><ul>');
      for I := 0 to R.Trailer.Count - 1 do
        W.Write('<li>' + R.Trailer[I] + '</li>');
      W.Write('</ul>');
    end;

    W.Write('</body></html>');
  end;

  procedure ChunkedHandler(W: TResponseWriter; R: TRequest);
  var
    I: integer;
  begin
    W.Header.SetValue('Content-Type', 'text/plain');
    W.Trailer.AddValue('X-Checksum', 'abc123');
    W.Trailer.AddValue('X-Processing-Time', '42ms');

    W.WriteHeader(200);

    for I := 1 to 5 do
    begin
      W.Write('Chunk ' + IntToStr(I) + #13#10);
      Sleep(100);
    end;
  end;

  procedure JSONHandler(W: TResponseWriter; R: TRequest);
  begin
    W.Header.SetValue('Content-Type', 'application/json');
    W.Write('{"status":"ok","chunked":' +
      LowerCase(BoolToStr(R.HasChunkedEncoding, True)) + ',"body_length":' +
      IntToStr(Length(R.Body)) + '}');
  end;

var
  Srv: THTTPServer;
  UseTLS: boolean;

begin
  UseTLS := False;

  Srv := THTTPServer.Create;
  try
    Srv.Use(@RecoveryMiddleware);
    Srv.Use(@LoggingMiddleware);
    Srv.HandleFunc('/', @RootHandler);
    Srv.HandleFunc('/chunked', @ChunkedHandler);
    Srv.HandleFunc('/api/test', @JSONHandler);
    Srv.HandleFuncHost('localhost', '/static/', FileServer('./public'));
    Srv.HandleFuncHost('localhost', '/static/', FileServer('./public'));

    if UseTLS then
      Srv.ListenAndServeTLS(':8443', 'server.crt', 'server.key')
    else
      Srv.ListenAndServe(':8080');
  finally
    Srv.Free;
  end;
end.
```
### AdvancedHTTPRouter: The middleware high-perfomance router

**AdvancedHTTPRouter** is a high-performance, lightweight HTTP router designed specifically to integrate with your `AdvancedHTTPServer`. It provides a modern, structured way to define routes, handle requests, and organize application logic, inspired by popular frameworks like Gin (Go) or Echo.

#### Key Features

- **Efficient Routing with Radix Tree**  
  Uses a  radix tree (trie) for route matching. This ensures very fast lookups , even with hundreds or thousands of routes. It handles:
  - Static paths: `/users/list`
  - Named parameters: `/users/:id` → access via `ctx.Param('id')`
  - Wildcard catch-all: `/files/*path` → captures everything after

- **HTTP Method Support**  
  Dedicated methods for all standard verbs:
  - `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`
  - `Any()` for routes that respond to all methods
  - Automatic fallback for `HEAD` to `GET` handlers if no explicit `HEAD` route exists

- **Middleware System**  
  - Global middleware via `router.Use(...)`
  - Per-group middleware
  - Middleware can call `ctx.Next()` to continue the chain or `ctx.Abort()` to stop it
  - Middleware and handlers form a chain — you can attach multiple handlers per route

- **Route Grouping**  
  Powerful grouping with prefixes and nested groups:
  ```pascal
  api := router.Group('/api/v1');
  api.Use(AuthMiddleware);
  users := api.Group('/users');
  users.GET('/:id', GetUserHandler);
  ```
  Groups automatically inherit prefixes and can have their own middleware.

- **Convenient Context Object** (`THTTPRouterContext`)  
  Passed to every handler:
  - `Param(name)`, `Query(name)`, `Header(name)` for easy access
  - Response helpers:
    - `Status(code)`
    - `Text(code, body)`
    - `JSON(code, TJSONData)` or `JSONText(code, rawJSON)`
  - `Next()` / `Abort()` for chain control
  - Access to original `Request` and `ResponseWriter`

- **Error Handling**  
  - Custom 404 (Not Found) handlers via `NoRoute(...)`
  - Custom 405 (Method Not Allowed) handlers via `NoMethod(...)`
  - Defaults provided if not overridden

- **Seamless Integration**  
  Simply call `router.Mount()` to register the router as the main handler on your `THTTPServer`.



Good luck and have fun building web applications in Pascal! 🚀

