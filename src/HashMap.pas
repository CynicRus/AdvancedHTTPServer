{******************************************************************************
   THashMap - Generic hashmap implementation for Free Pascal

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

unit HashMap;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}

interface

uses
  SysUtils;

type

  { Generic hashmap class }

  { THashMap }

  generic THashMap<TKey, TValue> = class
  public
  type
    TIterationCallback = function(const Key: TKey; const Value: TValue;
      Context: Pointer): boolean;
    THashFunction = function(const Key: TKey): longword;
    TCompareFunction = function(const Key1, Key2: TKey): integer;
    TUpdateProc = procedure(const Key: TKey; var Value: TValue; Context: Pointer);

    PListNode = ^TListNode;

    TListNode = record
      Next: PListNode;
      Key: TKey;
      Value: TValue;
    end;

  private
  const
    DefaultCapacity = 8;
    GrowthFactor = 2;

  private
    FBuckets: array of PListNode;
    FSize: SizeUInt;
    FCapacity: SizeUInt;
    FBucketsFilled: SizeUInt;
    FHashFunction: THashFunction;
    FCompareFunction: TCompareFunction;

    { Node Pool }
    FFreeList: PListNode;

    { Internal functions }
    function AllocNode: PListNode; inline;
    procedure FreeNode(Node: PListNode); inline;

    function ListNew(Next: PListNode; const Key: TKey; const Value: TValue): PListNode;
    function ListInsert(var Head: PListNode; const Key: TKey;
      const Value: TValue): boolean;
    function ListFind(Head: PListNode; const Key: TKey; out Value: TValue): boolean;
    function ListRemove(var List: PListNode; const Key: TKey;
      out Value: TValue): boolean;
    function ListIterate(Head: PListNode; Callback: TIterationCallback;
      Context: Pointer): boolean;
    procedure ListFree(Head: PListNode);
    function ListDuplicate(Head: PListNode): PListNode;

    function HashIndex(const Key: TKey): SizeUInt;
    function CompareKeys(const Key1, Key2: TKey): integer;
    function DefaultHash(const Key: TKey): longword;
    function DefaultCompare(const Key1, Key2: TKey): integer;
  public
    constructor Create; overload;
    constructor Create(HashFunc: THashFunction; CompareFunc: TCompareFunction); overload;
    destructor Destroy; override;
    procedure Reserve(MinCapacity: SizeUInt);

    { API functions }
    procedure Init;
    procedure Grow;
    function Insert(const Key: TKey; const Value: TValue): boolean;
    // Returns True if overwritten
    function Remove(const Key: TKey; out Value: TValue): boolean; overload;
    function Remove(const Key: TKey): boolean; overload;
    function Get(const Key: TKey; out Value: TValue): boolean;
    function Has(const Key: TKey): boolean;
    function GetSize: SizeUInt;
    procedure Clear;
    procedure Iterate(Callback: TIterationCallback; Context: Pointer);
    procedure Duplicate(Dest: THashMap);
    function Update(const Key: TKey; Proc: TUpdateProc; Context: Pointer): boolean;

    property Size: SizeUInt read FSize;
    property Capacity: SizeUInt read FCapacity;
  end;

  { String-specialized hashmap }
  generic TStringHashMap<TValue> = class(specialize THashMap<string, TValue>)
  public
    constructor Create;
  end;

function StringHash(const Key: string): longword; inline;
function StringCompare(const Key1, Key2: string): integer; inline;

function IsPowerOfTwo(x: SizeUInt): boolean; inline;
function NextPowerOfTwo(x: SizeUInt): SizeUInt; inline;
function MaxLoadSize(Cap: SizeUInt): SizeUInt; inline;

implementation

function IsPowerOfTwo(x: SizeUInt): boolean; inline;
begin
  Result := (x <> 0) and ((x and (x - 1)) = 0);
end;

function NextPowerOfTwo(x: SizeUInt): SizeUInt; inline;
begin
  if x <= 1 then Exit(1);
  Dec(x);
  x := x or (x shr 1);
  x := x or (x shr 2);
  x := x or (x shr 4);
  x := x or (x shr 8);
  x := x or (x shr 16);
  {$IFDEF CPU64}
  x := x or (x shr 32);
  {$ENDIF}
  Result := x + 1;
end;

function MaxLoadSize(Cap: SizeUInt): SizeUInt; inline;
begin
  Result := (Cap * 3) div 4;
end;

{ THashMap }

constructor THashMap.Create;
begin
  inherited Create;
  FHashFunction := nil;
  FCompareFunction := nil;
  FSize := 0;
  FCapacity := 0;
  FBucketsFilled := 0;
  FFreeList := nil; // Init pool
  SetLength(FBuckets, 0);
end;

constructor THashMap.Create(HashFunc: THashFunction; CompareFunc: TCompareFunction);
begin
  Create;
  FHashFunction := HashFunc;
  FCompareFunction := CompareFunc;
end;

destructor THashMap.Destroy;
var
  i: SizeUInt;
  Node: PListNode;
begin
  if FCapacity > 0 then
  begin
    for i := 0 to FCapacity - 1 do
      ListFree(FBuckets[i]);
  end;
  SetLength(FBuckets, 0);

  // Free remaining nodes in the pool
  while FFreeList <> nil do
  begin
    Node := FFreeList;
    FFreeList := FFreeList^.Next;
    Dispose(Node);
  end;

  inherited Destroy;
end;

procedure THashMap.Reserve(MinCapacity: SizeUInt);
var
  TargetCap: SizeUInt;
begin
  TargetCap := NextPowerOfTwo((MinCapacity * 4) div 3);
  if TargetCap > FCapacity then
  begin
    if FCapacity = 0 then
    begin
      FCapacity := TargetCap;
      FSize := 0;
      FBucketsFilled := 0;
      SetLength(FBuckets, FCapacity);
      FillChar(FBuckets[0], FCapacity * SizeOf(Pointer), 0);
    end
    else
    begin
      FCapacity := TargetCap div GrowthFactor;
      Grow;
    end;
  end;
end;

procedure THashMap.Init;
var
  i: SizeUInt;
begin
  FCapacity := DefaultCapacity;
  FSize := 0;
  FBucketsFilled := 0;
  SetLength(FBuckets, FCapacity);
  for i := 0 to FCapacity - 1 do
    FBuckets[i] := nil;
end;

{ Node Pool Implementation }

function THashMap.AllocNode: PListNode; inline;
begin
  if FFreeList <> nil then
  begin
    Result := FFreeList;
    FFreeList := FFreeList^.Next;
  end
  else
    New(Result);
end;

procedure THashMap.FreeNode(Node: PListNode); inline;
begin
  Node^.Next := FFreeList;
  FFreeList := Node;
end;

function THashMap.ListNew(Next: PListNode; const Key: TKey;
  const Value: TValue): PListNode;
begin
  Result := AllocNode;
  Result^.Next := Next;
  Result^.Key := Key;
  Result^.Value := Value;
end;

function THashMap.CompareKeys(const Key1, Key2: TKey): integer;
begin
  if Assigned(FCompareFunction) then
    Result := FCompareFunction(Key1, Key2)
  else
    Result := DefaultCompare(Key1, Key2);
end;

function THashMap.DefaultHash(const Key: TKey): longword;
begin
  raise Exception.Create('DefaultHash is not safe for generic TKey. Provide a HashFunc.');
end;

function THashMap.ListInsert(var Head: PListNode; const Key: TKey;
  const Value: TValue): boolean;
var
  Cur, Prev: PListNode;
begin
  Cur := Head;
  Prev := nil;

  while Cur <> nil do
  begin
    if CompareKeys(Key, Cur^.Key) = 0 then
    begin
      Cur^.Value := Value;
      Exit(True); // overwritten
    end;
    Prev := Cur;
    Cur := Cur^.Next;
  end;

  if Prev = nil then
    Head := ListNew(nil, Key, Value)
  else
    Prev^.Next := ListNew(nil, Key, Value);

  Result := False;
end;

function THashMap.ListFind(Head: PListNode; const Key: TKey; out Value: TValue): boolean;
begin
  while Head <> nil do
  begin
    if CompareKeys(Head^.Key, Key) = 0 then
    begin
      Value := Head^.Value;
      Exit(True);
    end;
    Head := Head^.Next;
  end;
  Result := False;
end;

function THashMap.ListRemove(var List: PListNode; const Key: TKey;
  out Value: TValue): boolean;
var
  Head, Prev: PListNode;
begin
  Result := False;
  if List = nil then
    Exit;

  Head := List;
  Prev := nil;

  while Head <> nil do
  begin
    if CompareKeys(Head^.Key, Key) = 0 then
    begin
      Value := Head^.Value;

      if Prev = nil then
        List := Head^.Next
      else
        Prev^.Next := Head^.Next;

      FreeNode(Head); // Return to pool
      Exit(True);
    end;

    Prev := Head;
    Head := Head^.Next;
  end;
end;

function THashMap.ListIterate(Head: PListNode; Callback: TIterationCallback;
  Context: Pointer): boolean;
begin
  if not Assigned(Callback) then
    Exit(True);

  Result := True;
  while Head <> nil do
  begin
    if not Callback(Head^.Key, Head^.Value, Context) then
      Exit(False);
    Head := Head^.Next;
  end;
end;

procedure THashMap.ListFree(Head: PListNode);
var
  Next: PListNode;
begin
  while Head <> nil do
  begin
    Next := Head^.Next;
    FreeNode(Head); // Return to pool
    Head := Next;
  end;
end;

function THashMap.ListDuplicate(Head: PListNode): PListNode;
var
  NewHead, NewNext: PListNode;
begin
  if Head = nil then
    Exit(nil);

  NewHead := ListNew(nil, Head^.Key, Head^.Value);
  NewNext := NewHead;

  while Head^.Next <> nil do
  begin
    Head := Head^.Next;
    NewNext^.Next := ListNew(nil, Head^.Key, Head^.Value);
    NewNext := NewNext^.Next;
  end;

  Result := NewHead;
end;


function THashMap.DefaultCompare(const Key1, Key2: TKey): integer;
begin
  raise Exception.Create(
    'DefaultCompare is not safe for generic TKey. Provide a CompareFunc.');
end;

function THashMap.HashIndex(const Key: TKey): SizeUInt;
var
  Hash: longword;
begin
  if not IsPowerOfTwo(FCapacity) then
    raise Exception.Create('Capacity must be power of two');

  if Assigned(FHashFunction) then
    Hash := FHashFunction(Key)
  else
    Hash := DefaultHash(Key);

  Result := Hash and (FCapacity - 1);
end;

procedure THashMap.Grow;
var
  NewCapacity, Target: SizeUInt;
  OldBuckets: array of PListNode;
  OldCapacity: SizeUInt;
  i: SizeUInt;
  Node, Next: PListNode;
  NewIdx: SizeUInt;
  Hash: longword;
begin
  if FCapacity = 0 then
  begin
    Init;
    Exit;
  end;

  // Target capacity using GrowthFactor
  Target := FCapacity * GrowthFactor;
  if Target <= FCapacity then
  begin
    // overflow or GrowthFactor <= 1 scenario
    Target := FCapacity + 1;
    if Target <= FCapacity then Exit;
  end;

  NewCapacity := NextPowerOfTwo(Target);
  if NewCapacity <= FCapacity then
    Exit;

  OldBuckets := FBuckets;
  OldCapacity := FCapacity;

  FCapacity := NewCapacity;
  SetLength(FBuckets, FCapacity);
  for i := 0 to FCapacity - 1 do
    FBuckets[i] := nil;

  FBucketsFilled := 0;

  for i := 0 to OldCapacity - 1 do
  begin
    Node := OldBuckets[i];
    while Node <> nil do
    begin
      Next := Node^.Next;

      if Assigned(FHashFunction) then
        Hash := FHashFunction(Node^.Key)
      else
        Hash := DefaultHash(Node^.Key);

      NewIdx := Hash and (FCapacity - 1);

      Node^.Next := FBuckets[NewIdx];
      if FBuckets[NewIdx] = nil then
        Inc(FBucketsFilled);
      FBuckets[NewIdx] := Node;

      Node := Next;
    end;
  end;

  FSize := FSize;
  SetLength(OldBuckets, 0);
end;


function THashMap.Insert(const Key: TKey; const Value: TValue): boolean;
var
  Idx: SizeUInt;
  WasEmpty: boolean;
begin
  if FCapacity = 0 then
    Init;

  if (FSize + 1) > MaxLoadSize(FCapacity) then
    Grow;

  Idx := HashIndex(Key);
  WasEmpty := (FBuckets[Idx] = nil);

  Result := ListInsert(FBuckets[Idx], Key, Value);

  if not Result then // new key
  begin
    Inc(FSize);
    if WasEmpty then
      Inc(FBucketsFilled);
  end;
end;

function THashMap.Remove(const Key: TKey; out Value: TValue): boolean;
var
  Idx: SizeUInt;
begin
  if FCapacity = 0 then
    Exit(False);

  Idx := HashIndex(Key);
  Result := ListRemove(FBuckets[Idx], Key, Value);

  if Result then
  begin
    if FBuckets[Idx] = nil then
      Dec(FBucketsFilled);
    Dec(FSize);
  end;
end;

function THashMap.Remove(const Key: TKey): boolean;
var
  Dummy: TValue;
begin
  Result := Remove(Key, Dummy);
end;

function THashMap.Get(const Key: TKey; out Value: TValue): boolean;
var
  Idx: SizeUInt;
begin
  if FCapacity = 0 then
    Exit(False);

  Idx := HashIndex(Key);
  Result := ListFind(FBuckets[Idx], Key, Value);
end;

function THashMap.Has(const Key: TKey): boolean;
var
  Dummy: TValue;
begin
  Result := Get(Key, Dummy);
end;

function THashMap.GetSize: SizeUInt;
begin
  Result := FSize;
end;

procedure THashMap.Clear;
var
  i: SizeUInt;
begin
  if FCapacity = 0 then Exit;

  for i := 0 to FCapacity - 1 do
  begin
    ListFree(FBuckets[i]);
    FBuckets[i] := nil;
  end;

  FSize := 0;
  FBucketsFilled := 0;
end;

procedure THashMap.Iterate(Callback: TIterationCallback; Context: Pointer);
var
  i: SizeUInt;
begin
  if not Assigned(Callback) then
    Exit;

  for i := 0 to FCapacity - 1 do
  begin
    if not ListIterate(FBuckets[i], Callback, Context) then
      Break;
  end;
end;

procedure THashMap.Duplicate(Dest: THashMap);
var
  i: SizeUInt;
begin
  if Dest = nil then
    raise Exception.Create('Destination hashmap is nil');

  if FCapacity = 0 then
  begin
    Dest.FSize := 0;
    Dest.FCapacity := 0;
    Dest.FBucketsFilled := 0;
    SetLength(Dest.FBuckets, 0);
    Exit;
  end;

  Dest.FCapacity := FCapacity;
  Dest.FSize := FSize;
  Dest.FBucketsFilled := FBucketsFilled;
  Dest.FHashFunction := FHashFunction;
  Dest.FCompareFunction := FCompareFunction;

  SetLength(Dest.FBuckets, Dest.FCapacity);
  for i := 0 to FCapacity - 1 do
    Dest.FBuckets[i] := ListDuplicate(FBuckets[i]);
end;

function THashMap.Update(const Key: TKey; Proc: TUpdateProc; Context: Pointer): boolean;
var
  Idx: SizeUInt;
  Node: PListNode;
begin
  if not Assigned(Proc) then Exit(False);
  if FCapacity = 0 then Exit(False);

  Idx := HashIndex(Key);
  Node := FBuckets[Idx];

  while Node <> nil do
  begin
    if CompareKeys(Node^.Key, Key) = 0 then
    begin
      Proc(Node^.Key, Node^.Value, Context);
      Exit(True);
    end;
    Node := Node^.Next;
  end;

  Result := False;
end;

{ TStringHashMap }

constructor TStringHashMap.Create;
begin
  inherited Create(@StringHash, @StringCompare);
end;


function StringHash(const Key: string): longword; inline;
var
  P: pbyte;
  Len: SizeInt;
begin
  Result := $811c9dc5;

  Len := Length(Key);
  if Len = 0 then Exit;

  P := pbyte(Pointer(Key));

  while Len > 0 do
  begin
    Result := (Result xor P^) * $01000193;
    Inc(P);
    Dec(Len);
  end;
end;


function StringCompare(const Key1, Key2: string): integer; inline;
var
  L1, L2: SizeInt;
begin
  if Pointer(Key1) = Pointer(Key2) then
    Exit(0);

  if Pointer(Key1) = nil then Exit(-1);
  if Pointer(Key2) = nil then Exit(1);

  L1 := Length(Key1);
  L2 := Length(Key2);

  if L1 <> L2 then
  begin
    if L1 < L2 then Exit(-1)
    else
      Exit(1);
  end;

  Result := CompareByte(pbyte(Key1)^, pbyte(Key2)^, L1);
end;

end.
