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

unit AdvancedHTTPMonitoring;

{$mode objfpc}{$H+}{$J-}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, DateUtils, Math, syncobjs,
  AdvancedHTTPServer, AdvancedHTTPRouter;

type
  TAlertProc = reference to procedure(const Line: string);

  TMonitoringConfig = record
    Enabled: boolean;

    // Paths
    MetricsPath: string;      // default: "/metrics"
    HealthPrefix: string;     // default: "/health"
    LivePath: string;         // default: "/health/live"
    ReadyPath: string;        // default: "/health/ready"
    StartupPath: string;      // default: "/health/startup"

    PreferJSON: boolean;

    // Histogram buckets in ms (Prometheus style)
    DurationBucketsMS: array of int64; // e.g. [5,10,25,50,100,250,500,1000,2500,5000]

    // Alerting
    EnableAlerts: boolean;
    AlertMinIntervalSec: integer; // rate-limit for alerts
    AlertOn5xx: boolean;
    AlertOnPanic: boolean;
    AlertOnHighErrorRate: boolean;
    ErrorRateWindowSec: integer; // sliding-ish window (simple buckets)
    ErrorRateThreshold: double;  // e.g. 0.2 = 20% 5xx

    // Readiness heuristics (optional)
    EnableReadinessLoadCheck: boolean;
    MaxActiveConnectionsForReady: integer; // 0 = ignore
    StartupGraceSec: integer;              // for /health/startup

    // Security: allow exposing /metrics publicly?
    MetricsAllowRemote: boolean; // if false: only localhost
  end;
  
  type
  TCounterKey = record
    Method: string;
    Route: string;
    Status: string;
  end;

  THistKey = record
    Method: string;
    Route: string;
    Status: string;
  end;

  THist = record
    Count: int64;
    SumMS: double;
    Buckets: array of int64; // same length as cfg buckets, cumulative counts
  end;

  TMonitoringState = class
  public
    Cfg: TMonitoringConfig;
    Server: THTTPServer;

    StartAt: TDateTime;

    Lock: TCriticalSection;

    Inflight: int64;

    ReqCounts: TStringList;

    // key = method|route|status -> packed hist
    Histograms: TStringList;

    // Error-rate tracking: ring of seconds buckets
    ErrWinSec: integer;
    ErrBuckets5xx: array of int64;
    ErrBucketsAll: array of int64;
    ErrBucketStartSec: int64; // unix seconds aligned
    ErrIdx: integer;

    LastAlertAt: TDateTime;
    OnAlert: TAlertProc;

    constructor Create(const ACfg: TMonitoringConfig; AServer: THTTPServer);
    destructor Destroy; override;

    function NowMS: int64;
    function UnixSecNow: int64;

    function IsLocalhost(const R: TRequest): boolean;

    function Key3(const Method, Route, Status: string): string;

    procedure IncInflight;
    procedure DecInflight;

    procedure ObserveRequest(const Method, Route: string; StatusCode: integer; DurMS: int64);

    function BucketsText(const CfgBuckets: array of int64; const H: THist; const BaseLabels: string): string;

    function BuildMetricsText: string;

    // Alerts
    procedure MaybeAlertOnResult(const Method, Route: string; StatusCode: integer; DurMS: int64);
    procedure MaybeAlertOnPanic(const Where, Msg: string);

    procedure AdvanceErrorWindow;
    procedure AddToErrorWindow(StatusCode: integer);

    function ReadyOK(out Reason: string): boolean;
    function StartupOK(out Reason: string): boolean;
  end;

function MonitoringDefaultConfig: TMonitoringConfig;

function MonitoringServerMiddleware(const Cfg: TMonitoringConfig; const Server: THTTPServer = nil): TMiddleware;
function MonitoringRouterMiddleware(const Cfg: TMonitoringConfig; const Server: THTTPServer = nil): TRouterMiddleware;

procedure MountMonitoringEndpoints(const Router: THTTPRouter; const Cfg: TMonitoringConfig; const Server: THTTPServer = nil);

implementation


function MonitoringDefaultConfig: TMonitoringConfig;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Enabled := True;

  Result.MetricsPath := '/metrics';
  Result.HealthPrefix := '/health';
  Result.LivePath := '/health/live';
  Result.ReadyPath := '/health/ready';
  Result.StartupPath := '/health/startup';

  Result.PreferJSON := True;

  SetLength(Result.DurationBucketsMS, 10);
  Result.DurationBucketsMS[0] := 5;
  Result.DurationBucketsMS[1] := 10;
  Result.DurationBucketsMS[2] := 25;
  Result.DurationBucketsMS[3] := 50;
  Result.DurationBucketsMS[4] := 100;
  Result.DurationBucketsMS[5] := 250;
  Result.DurationBucketsMS[6] := 500;
  Result.DurationBucketsMS[7] := 1000;
  Result.DurationBucketsMS[8] := 2500;
  Result.DurationBucketsMS[9] := 5000;

  Result.EnableAlerts := True;
  Result.AlertMinIntervalSec := 10;
  Result.AlertOn5xx := True;
  Result.AlertOnPanic := True;

  Result.AlertOnHighErrorRate := True;
  Result.ErrorRateWindowSec := 60;
  Result.ErrorRateThreshold := 0.2;

  Result.EnableReadinessLoadCheck := True;
  Result.MaxActiveConnectionsForReady := 0; // ignore by default
  Result.StartupGraceSec := 0;

  Result.MetricsAllowRemote := True;
end;

{ TMonitoringState }

constructor TMonitoringState.Create(const ACfg: TMonitoringConfig; AServer: THTTPServer);
var
  i: integer;
begin
  inherited Create;
  Cfg := ACfg;
  Server := AServer;
  StartAt := Now;

  Lock := TCriticalSection.Create;

  Inflight := 0;

  ReqCounts := TStringList.Create;
  ReqCounts.CaseSensitive := False;
  ReqCounts.NameValueSeparator := '=';

  Histograms := TStringList.Create;
  Histograms.CaseSensitive := False;
  Histograms.NameValueSeparator := '=';

  ErrWinSec := Max(1, Cfg.ErrorRateWindowSec);
  SetLength(ErrBuckets5xx, ErrWinSec);
  SetLength(ErrBucketsAll, ErrWinSec);
  for i := 0 to ErrWinSec-1 do
  begin
    ErrBuckets5xx[i] := 0;
    ErrBucketsAll[i] := 0;
  end;
  ErrBucketStartSec := 0;
  ErrIdx := 0;

  LastAlertAt := 0;
  OnAlert := nil;
end;

destructor TMonitoringState.Destroy;
begin
  Histograms.Free;
  ReqCounts.Free;
  Lock.Free;
  inherited Destroy;
end;

function TMonitoringState.NowMS: int64;
begin
  Result := GetTickCount64;
end;

function TMonitoringState.UnixSecNow: int64;
begin
  Result := DateTimeToUnix(Now);
end;

function TMonitoringState.IsLocalhost(const R: TRequest): boolean;
var
  ip: string;
begin
  ip := Trim(R.RemoteAddr);
  Result :=
    (ip = '127.0.0.1') or (ip = '::1') or (ip = 'localhost') or (ip = '') or
    (Pos('127.0.0.1', ip) > 0) or (Pos('::1', ip) > 0);
end;

function TMonitoringState.Key3(const Method, Route, Status: string): string;
begin
  Result := LowerCase(Method) + '|' + Route + '|' + Status;
end;

procedure TMonitoringState.IncInflight;
begin
  Lock.Enter;
  try
    Inc(Inflight);
  finally
    Lock.Leave;
  end;
end;

procedure TMonitoringState.DecInflight;
begin
  Lock.Enter;
  try
    if Inflight > 0 then Dec(Inflight);
  finally
    Lock.Leave;
  end;
end;

function PackHist(const H: THist): string;
var
  i: integer;
  s: string;
begin
  s := IntToStr(H.Count) + ';' + FloatToStr(H.SumMS);
  for i := 0 to High(H.Buckets) do
    s := s + ';' + IntToStr(H.Buckets[i]);
  Result := s;
end;

function UnpackHist(const Raw: string; BucketCount: integer; out H: THist): boolean;
var
  parts: TStringArray;
  i: integer;
begin
  Result := False;
  FillChar(H, SizeOf(H), 0);
  parts := Raw.Split([';']);
  if Length(parts) < 2 then Exit(False);

  H.Count := StrToInt64Def(parts[0], 0);
  H.SumMS := StrToFloatDef(parts[1], 0);

  SetLength(H.Buckets, BucketCount);
  for i := 0 to BucketCount-1 do
  begin
    if 2+i <= High(parts) then
      H.Buckets[i] := StrToInt64Def(parts[2+i], 0)
    else
      H.Buckets[i] := 0;
  end;

  Result := True;
end;

procedure TMonitoringState.AdvanceErrorWindow;
var
  nowSec, aligned: int64;
  steps, i: integer;
begin
  if not Cfg.AlertOnHighErrorRate then Exit;

  nowSec := UnixSecNow;
  aligned := nowSec; // 1-second buckets

  if ErrBucketStartSec = 0 then
  begin
    ErrBucketStartSec := aligned;
    ErrIdx := 0;
    Exit;
  end;

  steps := integer(aligned - ErrBucketStartSec);
  if steps <= 0 then Exit;

  // advance up to window size (if huge jump, just reset)
  if steps >= ErrWinSec then
  begin
    for i := 0 to ErrWinSec-1 do
    begin
      ErrBuckets5xx[i] := 0;
      ErrBucketsAll[i] := 0;
    end;
    ErrBucketStartSec := aligned;
    ErrIdx := 0;
    Exit;
  end;

  for i := 1 to steps do
  begin
    ErrIdx := (ErrIdx + 1) mod ErrWinSec;
    ErrBuckets5xx[ErrIdx] := 0;
    ErrBucketsAll[ErrIdx] := 0;
    Inc(ErrBucketStartSec);
  end;
end;

procedure TMonitoringState.AddToErrorWindow(StatusCode: integer);
begin
  if not Cfg.AlertOnHighErrorRate then Exit;

  AdvanceErrorWindow;
  Inc(ErrBucketsAll[ErrIdx]);
  if (StatusCode >= 500) and (StatusCode <= 599) then
    Inc(ErrBuckets5xx[ErrIdx]);
end;

procedure TMonitoringState.ObserveRequest(const Method, Route: string; StatusCode: integer; DurMS: int64);
var
  k, statusS: string;
  idx: integer;
  c: int64;

  hk: string;
  h: THist;

  bCount, i, j: integer;
begin
  statusS := IntToStr(StatusCode);
  k := Key3(Method, Route, statusS);

  Lock.Enter;
  try
    // counter
    idx := ReqCounts.IndexOfName(k);
    if idx < 0 then
      ReqCounts.Values[k] := '1'
    else
    begin
      c := StrToInt64Def(ReqCounts.ValueFromIndex[idx], 0);
      ReqCounts.ValueFromIndex[idx] := IntToStr(c + 1);
    end;

    // histogram
    bCount := Length(Cfg.DurationBucketsMS);
    hk := k;
    idx := Histograms.IndexOfName(hk);
    if (idx < 0) or (not UnpackHist(Histograms.ValueFromIndex[idx], bCount, h)) then
    begin
      FillChar(h, SizeOf(h), 0);
      SetLength(h.Buckets, bCount);
    end;

    Inc(h.Count);
    h.SumMS := h.SumMS + DurMS;

    for i := 0 to bCount-1 do
      if DurMS <= Cfg.DurationBucketsMS[i] then
      begin
        // for cumulative, increment this and all later
        j := i;
        while j <= bCount-1 do
        begin
          Inc(h.Buckets[j]);
          Inc(j);
        end;
        Break;
      end;

    // +Inf bucket is implicit in _count in Prometheus exposition; but we'll still expose explicit +Inf from Count
    if idx < 0 then
      Histograms.Values[hk] := PackHist(h)
    else
      Histograms.ValueFromIndex[idx] := PackHist(h);

    // error window
    AddToErrorWindow(StatusCode);
  finally
    Lock.Leave;
  end;
end;

procedure TMonitoringState.MaybeAlertOnResult(const Method, Route: string; StatusCode: integer; DurMS: int64);
var
  nowT: TDateTime;
  allow: boolean;

  total5xx, totalAll: int64;
  i: integer;
  rate: double;
  line: string;
begin
  if not Cfg.EnableAlerts then Exit;
  if not Assigned(OnAlert) then Exit;

  nowT := Now;

  Lock.Enter;
  try
    allow := (LastAlertAt = 0) or (SecondsBetween(nowT, LastAlertAt) >= Cfg.AlertMinIntervalSec);
    if not allow then Exit;

    // 5xx immediate
    if Cfg.AlertOn5xx and (StatusCode >= 500) and (StatusCode <= 599) then
    begin
      LastAlertAt := nowT;
      line := '[alert] http_5xx method=' + Method + ' route=' + Route +
              ' status=' + IntToStr(StatusCode) + ' dur_ms=' + IntToStr(DurMS);
      OnAlert(line);
      Exit;
    end;

    // high 5xx rate (window)
    if Cfg.AlertOnHighErrorRate then
    begin
      AdvanceErrorWindow;

      total5xx := 0;
      totalAll := 0;
      for i := 0 to ErrWinSec-1 do
      begin
        total5xx := total5xx + ErrBuckets5xx[i];
        totalAll := totalAll + ErrBucketsAll[i];
      end;

      if totalAll >= 20 then // don't alert on tiny sample
      begin
        rate := total5xx / Max(1.0, totalAll);
        if rate >= Cfg.ErrorRateThreshold then
        begin
          LastAlertAt := nowT;
          line := '[alert] high_5xx_rate window_sec=' + IntToStr(ErrWinSec) +
                  ' total=' + IntToStr(totalAll) + ' err5xx=' + IntToStr(total5xx) +
                  ' rate=' + FloatToStr(rate);
          OnAlert(line);
          Exit;
        end;
      end;
    end;

  finally
    Lock.Leave;
  end;
end;

procedure TMonitoringState.MaybeAlertOnPanic(const Where, Msg: string);
var
  nowT: TDateTime;
  allow: boolean;
begin
  if not Cfg.EnableAlerts then Exit;
  if not Cfg.AlertOnPanic then Exit;
  if not Assigned(OnAlert) then Exit;

  nowT := Now;
  Lock.Enter;
  try
    allow := (LastAlertAt = 0) or (SecondsBetween(nowT, LastAlertAt) >= Cfg.AlertMinIntervalSec);
    if not allow then Exit;
    LastAlertAt := nowT;
  finally
    Lock.Leave;
  end;

  OnAlert('[alert] panic where=' + Where + ' msg="' + StringReplace(Msg, #10, ' ', [rfReplaceAll]) + '"');
end;

function EscapeLabelValue(const S: string): string;
begin
  Result := StringReplace(S, '\', '\\', [rfReplaceAll]);
  Result := StringReplace(Result, '"', '\"', [rfReplaceAll]);
  Result := StringReplace(Result, #10, '\n', [rfReplaceAll]);
end;

function TMonitoringState.BucketsText(const CfgBuckets: array of int64; const H: THist; const BaseLabels: string): string;
var
  i: integer;
  labels: string;
begin
  Result := '';
  for i := 0 to High(CfgBuckets) do
  begin
    labels := BaseLabels + ',le="' + IntToStr(CfgBuckets[i]) + '"';
    Result := Result + 'http_request_duration_ms_bucket{' + labels + '} ' + IntToStr(H.Buckets[i]) + #10;
  end;
  // +Inf
  labels := BaseLabels + ',le="+Inf"';
  Result := Result + 'http_request_duration_ms_bucket{' + labels + '} ' + IntToStr(H.Count) + #10;
end;

function TMonitoringState.BuildMetricsText: string;
var
  sb: TStringBuilder;
  i: integer;
  k, raw, method, route, statusS: string;
  parts: TStringArray;

  cnt: int64;
  h: THist;

  up: double;
  ac: integer;
begin
  sb := TStringBuilder.Create;
  try
    sb.Append('# TYPE http_inflight_requests gauge').AppendLine;
    Lock.Enter;
    try
      sb.Append('http_inflight_requests ').Append(IntToStr(Inflight)).AppendLine;
    finally
      Lock.Leave;
    end;

    up := SecondsBetween(Now, StartAt);
    sb.Append('# TYPE process_uptime_seconds gauge').AppendLine;
    sb.Append('process_uptime_seconds ').Append(FloatToStr(up)).AppendLine;

    if Assigned(Server) then
    begin
      ac := Server.ActiveConnections;
      sb.Append('# TYPE process_active_connections gauge').AppendLine;
      sb.Append('process_active_connections ').Append(IntToStr(ac)).AppendLine;
    end;

    sb.Append('# TYPE http_requests_total counter').AppendLine;
    sb.Append('# TYPE http_request_duration_ms_bucket counter').AppendLine;
    sb.Append('# TYPE http_request_duration_ms_sum counter').AppendLine;
    sb.Append('# TYPE http_request_duration_ms_count counter').AppendLine;

    Lock.Enter;
    try
      // counters
      for i := 0 to ReqCounts.Count-1 do
      begin
        k := ReqCounts.Names[i];
        raw := ReqCounts.ValueFromIndex[i];
        cnt := StrToInt64Def(raw, 0);

        parts := k.Split(['|']);
        if Length(parts) <> 3 then Continue;
        method := parts[0];
        route := parts[1];
        statusS := parts[2];

        sb.Append('http_requests_total{method="').Append(EscapeLabelValue(UpperCase(method))).Append('",route="')
          .Append(EscapeLabelValue(route)).Append('",status="').Append(EscapeLabelValue(statusS)).Append('"} ')
          .Append(IntToStr(cnt)).AppendLine;
      end;

      // histograms
      for i := 0 to Histograms.Count-1 do
      begin
        k := Histograms.Names[i];
        raw := Histograms.ValueFromIndex[i];

        parts := k.Split(['|']);
        if Length(parts) <> 3 then Continue;
        method := parts[0];
        route := parts[1];
        statusS := parts[2];

        if not UnpackHist(raw, Length(Cfg.DurationBucketsMS), h) then Continue;

        // buckets
        sb.Append(BucketsText(Cfg.DurationBucketsMS, h,
          'method="' + EscapeLabelValue(UpperCase(method)) + '",route="' + EscapeLabelValue(route) + '",status="' + EscapeLabelValue(statusS) + '"'));

        // sum / count
        sb.Append('http_request_duration_ms_sum{method="').Append(EscapeLabelValue(UpperCase(method))).Append('",route="')
          .Append(EscapeLabelValue(route)).Append('",status="').Append(EscapeLabelValue(statusS)).Append('"} ')
          .Append(FloatToStr(h.SumMS)).AppendLine;

        sb.Append('http_request_duration_ms_count{method="').Append(EscapeLabelValue(UpperCase(method))).Append('",route="')
          .Append(EscapeLabelValue(route)).Append('",status="').Append(EscapeLabelValue(statusS)).Append('"} ')
          .Append(IntToStr(h.Count)).AppendLine;
      end;

    finally
      Lock.Leave;
    end;

    Result := sb.ToString;
  finally
    sb.Free;
  end;
end;

function TMonitoringState.ReadyOK(out Reason: string): boolean;
var
  ac: integer;
begin
  Reason := 'ok';
  if ShutdownRequested then
  begin
    Reason := 'shutting_down';
    Exit(False);
  end;

  if not Cfg.EnableReadinessLoadCheck then Exit(True);

  if (Cfg.MaxActiveConnectionsForReady > 0) and Assigned(Server) then
  begin
    ac := Server.ActiveConnections;
    if ac > Cfg.MaxActiveConnectionsForReady then
    begin
      Reason := 'too_many_active_connections';
      Exit(False);
    end;
  end;

  Result := True;
end;

function TMonitoringState.StartupOK(out Reason: string): boolean;
var
  up: integer;
begin
  Reason := 'ok';
  if Cfg.StartupGraceSec <= 0 then Exit(True);
  up := SecondsBetween(Now, StartAt);
  if up < Cfg.StartupGraceSec then
  begin
    Reason := 'starting';
    Exit(False);
  end;
  Result := True;
end;

procedure WriteHealth(W: TResponseWriter; const PreferJSON: boolean; Code: integer; const Status, Reason: string);
var
  body: string;
begin
  if W.HeadersSent then Exit;

  if PreferJSON then
  begin
    W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
    W.WriteHeader(Code);
    body := '{"status":"' + Status + '","reason":"' + StringReplace(Reason, '"', '\"', [rfReplaceAll]) + '"}';
    W.Write(body);
  end
  else
  begin
    W.Header.SetValue('Content-Type', 'text/plain; charset=utf-8');
    W.WriteHeader(Code);
    W.Write(Status + ' ' + Reason);
  end;
end;

procedure MetricsHandler(W: TResponseWriter; R: TRequest; S: TMonitoringState);
begin
  if (not S.Cfg.MetricsAllowRemote) and (not S.IsLocalhost(R)) then
  begin
    W.WriteHeader(403);
    W.Write('forbidden');
    Exit;
  end;

  W.Header.SetValue('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  W.WriteHeader(200);
  W.Write(S.BuildMetricsText);
end;

function MonitoringServerMiddleware(const Cfg: TMonitoringConfig; const Server: THTTPServer): TMiddleware;
var
  State: TMonitoringState;
begin
  State := TMonitoringState.Create(Cfg, Server);
  // default alert logger
  State.OnAlert := procedure(const Line: string) begin WriteLn(Line); end;

  Result := function(Next: THandlerFunc): THandlerFunc
  begin
    Result := procedure(W: TResponseWriter; R: TRequest)
    var
      start: int64;
      dur: int64;
      status: integer;
      route: string;
    begin
      if (not State.Cfg.Enabled) then
      begin
        Next(W, R);
        Exit;
      end;

      // Serve /metrics and /health at server level only if router is not used.
      // If you mount via router, you can skip this section.
      if (State.Cfg.MetricsPath <> '') and SameText(R.Path, State.Cfg.MetricsPath) then
      begin
        MetricsHandler(W, R, State);
        Exit;
      end;

      State.IncInflight;
      start := State.NowMS;

      // observe at finish
      W.OnBeforeFinish := procedure(WW: TResponseWriter; RR: TRequest)
      var
        d: int64;
        st: integer;
        rt: string;
      begin
        d := State.NowMS - start;
        st := WW.StatusCode;
        rt := RR.Path; // no router pattern available here
        State.ObserveRequest(RR.Method, rt, st, d);
        State.MaybeAlertOnResult(RR.Method, rt, st, d);
        State.DecInflight;
      end;

      try
        Next(W, R);
      except
        on E: Exception do
        begin
          State.MaybeAlertOnPanic('server', E.ClassName + ': ' + E.Message);
          raise;
        end;
      end;

      // if handler never called Finish (should in your server), OnBeforeFinish still fires in Finish
      dur := State.NowMS - start;
      status := W.StatusCode;
      route := R.Path;
      // NOTE: no direct observe here to avoid double count; OnBeforeFinish does it.
      // Keep local vars to avoid warnings.
      if (dur < 0) or (status = 0) or (route = '') then ;
    end;
  end;
end;

function MonitoringRouterMiddleware(const Cfg: TMonitoringConfig; const Server: THTTPServer): TRouterMiddleware;
var
  State: TMonitoringState;
begin
  State := TMonitoringState.Create(Cfg, Server);
  State.OnAlert := procedure(const Line: string) begin WriteLn(Line); end;

  Result := procedure(C: TObject)
  var
    Ctx: THTTPRouterContext;
    start: int64;
    route: string;
  begin
    Ctx := THTTPRouterContext(C);

    if not State.Cfg.Enabled then
    begin
      Ctx.Next;
      Exit;
    end;

    // skip monitoring endpoints themselves to avoid recursion/noise
    if (Ctx.R.Path = State.Cfg.MetricsPath) or
       (Ctx.R.Path = State.Cfg.LivePath) or
       (Ctx.R.Path = State.Cfg.ReadyPath) or
       (Ctx.R.Path = State.Cfg.StartupPath) then
    begin
      Ctx.Next;
      Exit;
    end;

    State.IncInflight;
    start := State.NowMS;

    Ctx.W.OnBeforeFinish := procedure(WW: TResponseWriter; RR: TRequest)
    var
      d: int64;
      st: integer;
      rt: string;
    begin
      d := State.NowMS - start;
      st := WW.StatusCode;
      rt := Ctx.RoutePattern;
      if rt = '' then rt := RR.Path;

      State.ObserveRequest(RR.Method, rt, st, d);
      State.MaybeAlertOnResult(RR.Method, rt, st, d);
      State.DecInflight;
    end;

    try
      Ctx.Next;
    except
      on E: Exception do
      begin
        route := Ctx.RoutePattern;
        if route = '' then route := Ctx.R.Path;
        State.MaybeAlertOnPanic('router', route + ' ' + E.ClassName + ': ' + E.Message);
        raise;
      end;
    end;
  end;
end;

procedure MountMonitoringEndpoints(const Router: THTTPRouter; const Cfg: TMonitoringConfig; const Server: THTTPServer);
var
  State: TMonitoringState;
begin
  if Router = nil then Exit;
  Router.Mount;
  State := TMonitoringState.Create(Cfg, Server);
  State.OnAlert := procedure(const Line: string) begin WriteLn(Line); end;

  // /metrics
  if Cfg.MetricsPath <> '' then
    Router.GET(Cfg.MetricsPath, [procedure(C: TObject)
    var
      Ctx: THTTPRouterContext;
    begin
      Ctx := THTTPRouterContext(C);
      MetricsHandler(Ctx.W, Ctx.R, State);
      Ctx.Abort;
    end]);

  // /health/live
  if Cfg.LivePath <> '' then
    Router.GET(Cfg.LivePath, [procedure(C: TObject)
    var
      Ctx: THTTPRouterContext;
    begin
      Ctx := THTTPRouterContext(C);
      if ShutdownRequested then
        WriteHealth(Ctx.W, Cfg.PreferJSON, 503, 'fail', 'shutting_down')
      else
        WriteHealth(Ctx.W, Cfg.PreferJSON, 200, 'ok', 'live');
      Ctx.Abort;
    end]);

  // /health/ready
  if Cfg.ReadyPath <> '' then
    Router.GET(Cfg.ReadyPath, [procedure(C: TObject)
    var
      Ctx: THTTPRouterContext;
      reason: string;
    begin
      Ctx := THTTPRouterContext(C);
      if State.ReadyOK(reason) then
        WriteHealth(Ctx.W, Cfg.PreferJSON, 200, 'ok', reason)
      else
        WriteHealth(Ctx.W, Cfg.PreferJSON, 503, 'fail', reason);
      Ctx.Abort;
    end]);

  // /health/startup
  if Cfg.StartupPath <> '' then
    Router.GET(Cfg.StartupPath, [procedure(C: TObject)
    var
      Ctx: THTTPRouterContext;
      reason: string;
    begin
      Ctx := THTTPRouterContext(C);
      if State.StartupOK(reason) then
        WriteHealth(Ctx.W, Cfg.PreferJSON, 200, 'ok', reason)
      else
        WriteHealth(Ctx.W, Cfg.PreferJSON, 503, 'fail', reason);
      Ctx.Abort;
    end]);
end;

end.
