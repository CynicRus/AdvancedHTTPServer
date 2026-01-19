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

unit AdvancedHTTPRouter;

{$mode objfpc}{$H+}{$J-}
{$modeswitch advancedrecords}
{$modeswitch functionreferences}
{$modeswitch anonymousfunctions}

interface

uses
  SysUtils, Classes, StrUtils, fpjson,
  AdvancedHTTPServer;

type
  TRouterHandler = reference to procedure(C: TObject);
  TRouterMiddleware = reference to procedure(C: TObject);
  TRouterHandlerList = array of TRouterHandler;

type
  { THTTPRouterContext }
  THTTPRouterContext = class
  private
    FIndex: integer;
    FAborted: boolean;
    FHandlers: TRouterHandlerList;
    FParams: TStringList;
  public
    W: TResponseWriter;
    R: TRequest;

    RoutePattern: string;
    RouteMethod: string;

    constructor Create(AW: TResponseWriter; AR: TRequest);
    destructor Destroy; override;

    procedure Next;
    procedure Abort;

    function Param(const Name: string): string;
    function Query(const Name: string): string;
    function Header(const Name: string): string;

    procedure Status(Code: integer);
    procedure Text(Code: integer; const S: string);
    procedure JSON(Code: integer; const Obj: TJSONData);
    procedure JSONText(Code: integer; const RawJSON: string);

    property Params: TStringList read FParams;
  end;

type
  TRouterMethod = (rmAny, rmGET, rmPOST, rmPUT, rmPATCH, rmDELETE, rmHEAD, rmOPTIONS);

type
  TPathTokenKind = (ptkStatic, ptkParam, ptkWildcard);

type
  TPathToken = record
    Kind: TPathTokenKind;
    Value: string; // static segment literal, or param/wildcard name (without :/*)
  end;

  TPathTokenArray = specialize TArray<TPathToken>;

type
  { TRadixNode }
  TRadixNode = class
  public
    Pattern: string;
    Handlers: TRouterHandlerList; // endpoint if non-empty

    // children
    StaticChildrenKeys: array of string;     // segment -> child (parallel arrays)
    StaticChildren: array of TRadixNode;

    ParamChild: TRadixNode;
    ParamName: string;

    WildcardChild: TRadixNode;
    WildcardName: string;

    constructor Create;
    destructor Destroy; override;

    procedure AddRoute(const FullPattern: string; const AHandlers: array of TRouterHandler);
    function GetValue(const PathToMatch: string; out Params: TStringList): TRadixNode;

  private
    function FindStaticChildIndex(const Seg: string): integer;
    function EnsureStaticChild(const Seg: string): TRadixNode;

    function TokenizePattern(const P: string): TPathTokenArray;
    function SplitPathToSegments(const P: string): TStringArray;
    function NormalizePattern(const P: string): string;
  end;

type
  { THTTPRouter }
  THTTPRouter = class
  private
    FServer: THTTPServer;
    FTrees: array[TRouterMethod] of TRadixNode;
    FGlobalMW: array of TRouterMiddleware;
    FNoRoute: TRouterHandlerList;
    FNoMethod: TRouterHandlerList;

    function NormalizePath(const S: string): string;
    function MethodFromString(const S: string): TRouterMethod;

    procedure AddRoute(AMethod: TRouterMethod; const Pattern: string;
      const Handlers: array of TRouterHandler);

    function MatchRoute(const ReqMethod, ReqPath: string;
      out RouteHandlers: TRouterHandlerList; out Params: TStringList;
      out MethodAllowed: boolean; out MatchedNode: TRadixNode): boolean;

    function BuildChain: THandlerFunc;
    function WrapMiddleware(const MW: TRouterMiddleware): TRouterHandler;

    procedure DefaultNoRoute(C: TObject);
    procedure DefaultNoMethod(C: TObject);
  public
    constructor Create(AServer: THTTPServer);
    destructor Destroy; override;

    procedure Mount;

    procedure Use(const MW: TRouterMiddleware);

    procedure Any(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure GET(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure POST(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure PUT(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure PATCH(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure Delete(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure HEAD(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure OPTIONS(const Pattern: string; const Handlers: array of TRouterHandler);

    procedure NoRoute(const Handlers: array of TRouterHandler);
    procedure NoMethod(const Handlers: array of TRouterHandler);

    function Group(const Prefix: string): TObject;
  end;

type
  { THTTPRouterGroup }
  THTTPRouterGroup = class
  private
    FRouter: THTTPRouter;
    FPrefix: string;
    FMW: array of TRouterMiddleware;
    procedure Add(AMethod: TRouterMethod; const Pattern: string;
      const Handlers: array of TRouterHandler);
  public
    constructor Create(ARouter: THTTPRouter; const APrefix: string);

    procedure Use(const MW: TRouterMiddleware);

    procedure Any(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure GET(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure POST(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure PUT(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure PATCH(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure Delete(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure HEAD(const Pattern: string; const Handlers: array of TRouterHandler);
    procedure OPTIONS(const Pattern: string; const Handlers: array of TRouterHandler);

    function Group(const Prefix: string): THTTPRouterGroup;
  end;

implementation

type
  TChainBuilder = class
    Chain: array of TRouterHandler;
    Router: THTTPRouter;
    procedure AppendHandler(const H: TRouterHandler);
    procedure AppendMany(const A: array of TRouterHandler);
    procedure AppendGlobalMW;
  end;

procedure TChainBuilder.AppendHandler(const H: TRouterHandler);
begin
  SetLength(Chain, Length(Chain) + 1);
  Chain[High(Chain)] := H;
end;

procedure TChainBuilder.AppendMany(const A: array of TRouterHandler);
var
  K: integer;
begin
  for K := 0 to High(A) do
    AppendHandler(A[K]);
end;

procedure TChainBuilder.AppendGlobalMW;
var
  K: integer;
begin
  for K := 0 to High(Router.FGlobalMW) do
    AppendHandler(Router.WrapMiddleware(Router.FGlobalMW[K]));
end;

{ THTTPRouterContext }

constructor THTTPRouterContext.Create(AW: TResponseWriter; AR: TRequest);
begin
  inherited Create;
  W := AW;
  R := AR;
  FIndex := -1;
  FAborted := False;

  FParams := TStringList.Create;
  FParams.NameValueSeparator := '=';
  FParams.StrictDelimiter := True;
  FParams.CaseSensitive := False;
end;

destructor THTTPRouterContext.Destroy;
begin
  FParams.Free;
  inherited Destroy;
end;

procedure THTTPRouterContext.Next;
begin
  if FAborted then Exit;

  Inc(FIndex);
  while (FIndex >= 0) and (FIndex < Length(FHandlers)) do
  begin
    if FAborted then Exit;
    FHandlers[FIndex](Self);
    Inc(FIndex);
  end;
end;

procedure THTTPRouterContext.Abort;
begin
  FAborted := True;
end;

function THTTPRouterContext.Param(const Name: string): string;
begin
  Result := FParams.Values[Name];
end;

function THTTPRouterContext.Query(const Name: string): string;
begin
  Result := R.QueryValue(Name);
end;

function THTTPRouterContext.Header(const Name: string): string;
begin
  Result := R.Header.GetValue(Name);
end;

procedure THTTPRouterContext.Status(Code: integer);
begin
  W.WriteHeader(Code);
end;

procedure THTTPRouterContext.Text(Code: integer; const S: string);
begin
  if not W.HeadersSent then
  begin
    W.Header.SetValue('Content-Type', 'text/plain; charset=utf-8');
    W.WriteHeader(Code);
  end;
  W.Write(S);
end;

procedure THTTPRouterContext.JSON(Code: integer; const Obj: TJSONData);
begin
  if not W.HeadersSent then
  begin
    W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
    W.WriteHeader(Code);
  end;
  W.Write(Obj.AsJSON);
end;

procedure THTTPRouterContext.JSONText(Code: integer; const RawJSON: string);
begin
  if not W.HeadersSent then
  begin
    W.Header.SetValue('Content-Type', 'application/json; charset=utf-8');
    W.WriteHeader(Code);
  end;
  W.Write(RawJSON);
end;

{ TRadixNode }

constructor TRadixNode.Create;
begin
  inherited Create;
  Pattern := '';
  SetLength(Handlers, 0);

  SetLength(StaticChildrenKeys, 0);
  SetLength(StaticChildren, 0);

  ParamChild := nil;
  ParamName := '';

  WildcardChild := nil;
  WildcardName := '';
end;

destructor TRadixNode.Destroy;
var
  I: integer;
begin
  for I := 0 to High(StaticChildren) do
    StaticChildren[I].Free;
  if ParamChild <> nil then ParamChild.Free;
  if WildcardChild <> nil then WildcardChild.Free;
  inherited Destroy;
end;

function TRadixNode.NormalizePattern(const P: string): string;
begin
  Result := P;
  if Result = '' then Result := '/';
  if Result[1] <> '/' then Result := '/' + Result;
  while Pos('//', Result) > 0 do
    Result := StringReplace(Result, '//', '/', [rfReplaceAll]);
  // strip trailing slash except root
  if (Length(Result) > 1) and (Result[Length(Result)] = '/') then
    Delete(Result, Length(Result), 1);
end;

function TRadixNode.SplitPathToSegments(const P: string): TStringArray;
var
  N: string;
begin
  N := NormalizePattern(P);
  if N = '/' then
    Exit(nil);
  // N starts with '/', so first segment is empty -> remove it
  Result := N.Split(['/']);
  // Result[0]=''
  if (Length(Result) > 0) and (Result[0] = '') then
    Result := Copy(Result, 1, Length(Result) - 1);
end;

function TRadixNode.TokenizePattern(const P: string): TPathTokenArray;
var
  Segs: TStringArray;
  I: integer;
  S: string;
  T: TPathToken;
begin
  Segs := SplitPathToSegments(P);
  SetLength(Result, Length(Segs));
  for I := 0 to High(Segs) do
  begin
    S := Segs[I];
    if S = '' then
      raise Exception.Create('Invalid route pattern (empty segment): ' + P);

    if (S[1] = ':') then
    begin
      if Length(S) = 1 then
        raise Exception.Create('Invalid param name in pattern: ' + P);
      T.Kind := ptkParam;
      T.Value := Copy(S, 2, MaxInt);
    end
    else if (S[1] = '*') then
    begin
      if Length(S) = 1 then
        raise Exception.Create('Invalid wildcard name in pattern: ' + P);
      if I <> High(Segs) then
        raise Exception.Create('Wildcard must be last segment: ' + P);
      T.Kind := ptkWildcard;
      T.Value := Copy(S, 2, MaxInt);
    end
    else
    begin
      if (Pos(':', S) > 0) or (Pos('*', S) > 0) then
        raise Exception.Create('Invalid pattern (":" or "*" inside static segment): ' + P);
      T.Kind := ptkStatic;
      T.Value := S;
    end;

    Result[I] := T;
  end;
end;

function TRadixNode.FindStaticChildIndex(const Seg: string): integer;
var
  I: integer;
begin
  for I := 0 to High(StaticChildrenKeys) do
    if StaticChildrenKeys[I] = Seg then
      Exit(I);
  Result := -1;
end;

function TRadixNode.EnsureStaticChild(const Seg: string): TRadixNode;
var
  Idx: integer;
begin
  Idx := FindStaticChildIndex(Seg);
  if Idx >= 0 then Exit(StaticChildren[Idx]);

  SetLength(StaticChildrenKeys, Length(StaticChildrenKeys) + 1);
  SetLength(StaticChildren, Length(StaticChildren) + 1);
  StaticChildrenKeys[High(StaticChildrenKeys)] := Seg;
  StaticChildren[High(StaticChildren)] := TRadixNode.Create;
  Result := StaticChildren[High(StaticChildren)];
end;

procedure TRadixNode.AddRoute(const FullPattern: string; const AHandlers: array of TRouterHandler);
var
  Tokens: TPathTokenArray;
  Cur: TRadixNode;
  I: integer;
  Tok: TPathToken;
  K: integer;
begin
  Tokens := TokenizePattern(FullPattern);
  Cur := Self;

  // root pattern "/"
  if Length(Tokens) = 0 then
  begin
    if Length(Cur.Handlers) > 0 then
      raise Exception.Create('Route conflict: ' + FullPattern);
    SetLength(Cur.Handlers, Length(AHandlers));
    for K := 0 to High(AHandlers) do Cur.Handlers[K] := AHandlers[K];
    Cur.Pattern := NormalizePattern(FullPattern);
    Exit;
  end;

  for I := 0 to High(Tokens) do
  begin
    Tok := Tokens[I];

    case Tok.Kind of
      ptkStatic:
        begin
          Cur := Cur.EnsureStaticChild(Tok.Value);
        end;

      ptkParam:
        begin
          if Cur.WildcardChild <> nil then
            raise Exception.Create('Route conflict: param after wildcard in ' + FullPattern);

          if Cur.ParamChild = nil then
          begin
            Cur.ParamChild := TRadixNode.Create;
            Cur.ParamName := Tok.Value;
          end
          else
          begin
            // If you want stricter: forbid different names at same position
            // (Gin allows, but last added name "wins" only for Param key; we keep first)
          end;
          Cur := Cur.ParamChild;
        end;

      ptkWildcard:
        begin
          if Cur.WildcardChild = nil then
          begin
            Cur.WildcardChild := TRadixNode.Create;
            Cur.WildcardName := Tok.Value;
          end;
          Cur := Cur.WildcardChild;
          // wildcard consumes the rest; loop ends anyway because tokenizer enforces last
        end;
    end;
  end;

  if Length(Cur.Handlers) > 0 then
    raise Exception.Create('Route conflict: ' + FullPattern);

  SetLength(Cur.Handlers, Length(AHandlers));
  for K := 0 to High(AHandlers) do Cur.Handlers[K] := AHandlers[K];
  Cur.Pattern := NormalizePattern(FullPattern);
end;

function TRadixNode.GetValue(const PathToMatch: string; out Params: TStringList): TRadixNode;
var
  Segs: TStringArray;
  Cur: TRadixNode;

  function EnsureParams: TStringList;
  begin
    if Params = nil then
    begin
      Params := TStringList.Create;
      Params.NameValueSeparator := '=';
      Params.StrictDelimiter := True;
      Params.CaseSensitive := False;
    end;
    Result := Params;
  end;

  function JoinRemainder(StartIndex: integer): string;
  var
    J: integer;
    B: string;
  begin
    B := '';
    for J := StartIndex to High(Segs) do
    begin
      if B <> '' then B := B + '/';
      B := B + Segs[J];
    end;
    Result := B;
  end;

var
  I, Idx: integer;
  Seg, Rem: string;
begin
  Result := nil;
  Params := nil;

  Segs := SplitPathToSegments(PathToMatch);
  Cur := Self;

  // Path == "/"
  if Length(Segs) = 0 then
  begin
    if Length(Cur.Handlers) > 0 then Exit(Cur);
    Exit(nil);
  end;

  for I := 0 to High(Segs) do
  begin
    Seg := Segs[I];

    // static
    Idx := Cur.FindStaticChildIndex(Seg);
    if Idx >= 0 then
    begin
      Cur := Cur.StaticChildren[Idx];
      Continue;
    end;

    // param next
    if Cur.ParamChild <> nil then
    begin
      EnsureParams.Values[Cur.ParamName] := Seg;
      Cur := Cur.ParamChild;
      Continue;
    end;

    // wildcard last
    if Cur.WildcardChild <> nil then
    begin
      Rem := JoinRemainder(I);
      EnsureParams.Values[Cur.WildcardName] := Rem;
      Cur := Cur.WildcardChild;
      // wildcard consumes all
      Break;
    end;

    Exit(nil);
  end;

  if (Cur <> nil) and (Length(Cur.Handlers) > 0) then
    Exit(Cur);

  Result := nil;
end;

{ THTTPRouter }

constructor THTTPRouter.Create(AServer: THTTPServer);
var
  M: TRouterMethod;
begin
  inherited Create;
  FServer := AServer;

  for M := Low(TRouterMethod) to High(TRouterMethod) do
    FTrees[M] := TRadixNode.Create;

  SetLength(FGlobalMW, 0);
  SetLength(FNoRoute, 0);
  SetLength(FNoMethod, 0);
end;

destructor THTTPRouter.Destroy;
var
  M: TRouterMethod;
begin
  for M := Low(TRouterMethod) to High(TRouterMethod) do
    FTrees[M].Free;
  inherited Destroy;
end;

function THTTPRouter.NormalizePath(const S: string): string;
begin
  Result := S;
  if Result = '' then Result := '/';
  if Result[1] <> '/' then Result := '/' + Result;
  while Pos('//', Result) > 0 do
    Result := StringReplace(Result, '//', '/', [rfReplaceAll]);
  if (Length(Result) > 1) and (Result[Length(Result)] = '/') then
    System.Delete(Result, Length(Result), 1);
end;

procedure THTTPRouter.Mount;
begin
  FServer.HandleFunc('/', BuildChain);
end;

procedure THTTPRouter.Use(const MW: TRouterMiddleware);
begin
  SetLength(FGlobalMW, Length(FGlobalMW) + 1);
  FGlobalMW[High(FGlobalMW)] := MW;
end;

function THTTPRouter.WrapMiddleware(const MW: TRouterMiddleware): TRouterHandler;
begin
  Result := procedure(C: TObject)
  begin
    MW(C);
    // gin-style: middleware self calls Next/Abort
  end;
end;

function THTTPRouter.MethodFromString(const S: string): TRouterMethod;
var
  U: string;
begin
  U := UpperCase(S);
  if U = 'GET' then Exit(rmGET);
  if U = 'POST' then Exit(rmPOST);
  if U = 'PUT' then Exit(rmPUT);
  if U = 'PATCH' then Exit(rmPATCH);
  if U = 'DELETE' then Exit(rmDELETE);
  if U = 'HEAD' then Exit(rmHEAD);
  if U = 'OPTIONS' then Exit(rmOPTIONS);
  Result := rmAny;
end;

procedure THTTPRouter.AddRoute(AMethod: TRouterMethod; const Pattern: string;
  const Handlers: array of TRouterHandler);
var
  P: string;
begin
  P := NormalizePath(Pattern);

  if AMethod = rmAny then
  begin
    AddRoute(rmGET, P, Handlers);
    AddRoute(rmPOST, P, Handlers);
    AddRoute(rmPUT, P, Handlers);
    AddRoute(rmPATCH, P, Handlers);
    AddRoute(rmDELETE, P, Handlers);
    AddRoute(rmHEAD, P, Handlers);
    AddRoute(rmOPTIONS, P, Handlers);
    Exit;
  end;

  FTrees[AMethod].AddRoute(P, Handlers);
end;

procedure THTTPRouter.Any(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmAny, Pattern, Handlers);
end;

procedure THTTPRouter.GET(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmGET, Pattern, Handlers);
end;

procedure THTTPRouter.POST(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmPOST, Pattern, Handlers);
end;

procedure THTTPRouter.PUT(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmPUT, Pattern, Handlers);
end;

procedure THTTPRouter.PATCH(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmPATCH, Pattern, Handlers);
end;

procedure THTTPRouter.Delete(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmDELETE, Pattern, Handlers);
end;

procedure THTTPRouter.HEAD(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmHEAD, Pattern, Handlers);
end;

procedure THTTPRouter.OPTIONS(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  AddRoute(rmOPTIONS, Pattern, Handlers);
end;

procedure THTTPRouter.NoRoute(const Handlers: array of TRouterHandler);
var
  I: integer;
begin
  SetLength(FNoRoute, Length(Handlers));
  for I := 0 to High(Handlers) do
    FNoRoute[I] := Handlers[I];
end;

procedure THTTPRouter.NoMethod(const Handlers: array of TRouterHandler);
var
  I: integer;
begin
  SetLength(FNoMethod, Length(Handlers));
  for I := 0 to High(Handlers) do
    FNoMethod[I] := Handlers[I];
end;

procedure THTTPRouter.DefaultNoRoute(C: TObject);
begin
  THTTPRouterContext(C).Text(404, '404 Not Found');
end;

procedure THTTPRouter.DefaultNoMethod(C: TObject);
begin
  THTTPRouterContext(C).Text(405, '405 Method Not Allowed');
end;

function THTTPRouter.MatchRoute(const ReqMethod, ReqPath: string;
  out RouteHandlers: TRouterHandlerList; out Params: TStringList;
  out MethodAllowed: boolean; out MatchedNode: TRadixNode): boolean;
var
  M: TRouterMethod;
  Node: TRadixNode;
  I: integer;
  TmpParams: TStringList;
  PathNorm: string;
begin
  Result := False;
  MethodAllowed := False;
  MatchedNode := nil;
  Params := nil;
  SetLength(RouteHandlers, 0);

  PathNorm := NormalizePath(ReqPath);
  M := MethodFromString(ReqMethod);

  // HEAD falls back to GET if no explicit HEAD handler is found
  if M = rmHEAD then
  begin
    Node := FTrees[rmHEAD].GetValue(PathNorm, Params);
    if (Node <> nil) and (Length(Node.Handlers) > 0) then
    begin
      MatchedNode := Node;
      SetLength(RouteHandlers, Length(Node.Handlers));
      for I := 0 to High(Node.Handlers) do RouteHandlers[I] := Node.Handlers[I];
      Exit(True);
    end;
    if Params <> nil then FreeAndNil(Params);

    Node := FTrees[rmGET].GetValue(PathNorm, Params);
    if (Node <> nil) and (Length(Node.Handlers) > 0) then
    begin
      MatchedNode := Node;
      SetLength(RouteHandlers, Length(Node.Handlers));
      for I := 0 to High(Node.Handlers) do RouteHandlers[I] := Node.Handlers[I];
      Exit(True);
    end;
    if Params <> nil then FreeAndNil(Params);
  end;

  Node := FTrees[M].GetValue(PathNorm, Params);
  if (Node <> nil) and (Length(Node.Handlers) > 0) then
  begin
    MatchedNode := Node;
    SetLength(RouteHandlers, Length(Node.Handlers));
    for I := 0 to High(Node.Handlers) do RouteHandlers[I] := Node.Handlers[I];
    Exit(True);
  end;
  if Params <> nil then FreeAndNil(Params);

  // 405 check
  for M := Low(TRouterMethod) to High(TRouterMethod) do
  begin
    if M = rmAny then Continue;
    TmpParams := nil;
    Node := FTrees[M].GetValue(PathNorm, TmpParams);
    if TmpParams <> nil then TmpParams.Free;
    if (Node <> nil) and (Length(Node.Handlers) > 0) then
    begin
      MethodAllowed := True;
      Break;
    end;
  end;

  Result := False;
end;

function THTTPRouter.BuildChain: THandlerFunc;
begin
  Result := procedure(W: TResponseWriter; R: TRequest)
  var
    RouteH: TRouterHandlerList;
    Params: TStringList;
    Allowed: boolean;
    Ctx: THTTPRouterContext;
    Builder: TChainBuilder;
    Node: TRadixNode;
    I: integer;
  begin
    Params := nil;
    Node := nil;
    Builder := TChainBuilder.Create;
    try
      Builder.Router := Self;
      if MatchRoute(R.Method, R.Path, RouteH, Params, Allowed, Node) then
      begin
        Builder.AppendGlobalMW;
        Builder.AppendMany(RouteH);
      end
      else
      begin
        Builder.AppendGlobalMW;
        if Allowed then
        begin
          if Length(FNoMethod) > 0 then Builder.AppendMany(FNoMethod)
          else Builder.AppendHandler(@Self.DefaultNoMethod);
        end
        else
        begin
          if Length(FNoRoute) > 0 then Builder.AppendMany(FNoRoute)
          else Builder.AppendHandler(@Self.DefaultNoRoute);
        end;
      end;

      Ctx := THTTPRouterContext.Create(W, R);
      try
        if Params <> nil then
          for I := 0 to Params.Count - 1 do
            Ctx.Params.Add(Params[I]);

        Ctx.FHandlers := Builder.Chain;
        Ctx.RouteMethod := R.Method;
        if (Node <> nil) and (Node.Pattern <> '') then Ctx.RoutePattern := Node.Pattern
        else Ctx.RoutePattern := '';

        Ctx.Next;
        W.Finish;
      finally
        Ctx.Free;
      end;
    finally
      Builder.Free;
      if Params <> nil then Params.Free;
    end;
  end;
end;

function THTTPRouter.Group(const Prefix: string): TObject;
begin
  Result := THTTPRouterGroup.Create(Self, NormalizePath(Prefix));
end;

{ THTTPRouterGroup }

constructor THTTPRouterGroup.Create(ARouter: THTTPRouter; const APrefix: string);
begin
  inherited Create;
  FRouter := ARouter;
  FPrefix := ARouter.NormalizePath(APrefix);
  SetLength(FMW, 0);
end;

procedure THTTPRouterGroup.Use(const MW: TRouterMiddleware);
begin
  SetLength(FMW, Length(FMW) + 1);
  FMW[High(FMW)] := MW;
end;

procedure THTTPRouterGroup.Add(AMethod: TRouterMethod; const Pattern: string;
  const Handlers: array of TRouterHandler);
var
  Full: string;
  Chain: array of TRouterHandler;
  I, N, K: integer;
begin
  Full := FRouter.NormalizePath(FPrefix + '/' + Pattern);

  SetLength(Chain, 0);

  // group middlewares
  for K := 0 to High(FMW) do
  begin
    SetLength(Chain, Length(Chain) + 1);
    Chain[High(Chain)] := FRouter.WrapMiddleware(FMW[K]);
  end;

  // endpoint handlers
  N := Length(Chain);
  SetLength(Chain, N + Length(Handlers));
  for I := 0 to High(Handlers) do
    Chain[N + I] := Handlers[I];

  FRouter.AddRoute(AMethod, Full, Chain);
end;

procedure THTTPRouterGroup.Any(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmAny, Pattern, Handlers);
end;

procedure THTTPRouterGroup.GET(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmGET, Pattern, Handlers);
end;

procedure THTTPRouterGroup.POST(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmPOST, Pattern, Handlers);
end;

procedure THTTPRouterGroup.PUT(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmPUT, Pattern, Handlers);
end;

procedure THTTPRouterGroup.PATCH(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmPATCH, Pattern, Handlers);
end;

procedure THTTPRouterGroup.Delete(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmDELETE, Pattern, Handlers);
end;

procedure THTTPRouterGroup.HEAD(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmHEAD, Pattern, Handlers);
end;

procedure THTTPRouterGroup.OPTIONS(const Pattern: string; const Handlers: array of TRouterHandler);
begin
  Add(rmOPTIONS, Pattern, Handlers);
end;

function THTTPRouterGroup.Group(const Prefix: string): THTTPRouterGroup;
begin
  Result := THTTPRouterGroup.Create(FRouter,
    FRouter.NormalizePath(FPrefix + '/' + Prefix));
end;

end.
