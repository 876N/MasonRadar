unit uMemoryScanner;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes;

type
  TStringCategory = (scURL, scDomain, scIPv4, scIPv6, scHostname, scOther);
  TExtractedString = record Value: string; Category: TStringCategory; Address: NativeUInt; end;
  TExtractedStringArray = array of TExtractedString;
  TRawMemString = record Value: string; Address: NativeUInt; Len: Integer; Protect: string; Encoding: string; end;
  TRawMemStringArray = array of TRawMemString;

function ScanProcessMemory(PID: DWORD; MinLen: Integer = 6; MaxReg: NativeUInt = 4*1024*1024): TExtractedStringArray;
function ScanProcessMemoryFull(PID: DWORD; MinLen: Integer = 4; MaxReg: NativeUInt = 4*1024*1024): TRawMemStringArray;
function ClassifyString(const S: string): TStringCategory;
function CategoryLabel(Cat: TStringCategory): string;
function ProtectToStr(P: DWORD): string;

implementation

const
  TLDS: array[0..49] of string = ('com','org','net','edu','gov','mil','int','io','co','us','uk','de','fr','jp','cn','ru','br','in','au','ca','it','es','nl','se','no','pl','ch','at','be','dk','fi','pt','ie','nz','me','tv','cc','info','biz','xyz','dev','app','ly','gg','to','sh','ws','fm','ai','sa');
  BAD_PRE: array[0..15] of string = ('system.','microsoft.','windows.','mscorlib.','mono.','internal.','interop.','reflection.','componentmodel.','collections.','runtime.','globalization.','diagnostics.','security.','codedom.','resources.');
  BAD_SUF: array[0..8] of string = ('.dll','.exe','.sys','.ocx','.drv','.cctor','.ctor','.pdb','.tlb');

function IsPrint(B: Byte): Boolean; inline; begin Result := (B>=32) and (B<=126); end;

function SW(const Lo: string; const L: array of string): Boolean;
var I,N: Integer;
begin Result:=False; for I:=Low(L) to High(L) do begin N:=Length(L[I]); if (N<=Length(Lo)) and (Copy(Lo,1,N)=L[I]) then begin Result:=True; Exit; end; end; end;

function EW(const Lo: string; const L: array of string): Boolean;
var I,N: Integer;
begin Result:=False; for I:=Low(L) to High(L) do begin N:=Length(L[I]); if (N<=Length(Lo)) and (Copy(Lo,Length(Lo)-N+1,N)=L[I]) then begin Result:=True; Exit; end; end; end;

function VTLD(const T: string): Boolean;
var I: Integer;
begin Result:=False; for I:=Low(TLDS) to High(TLDS) do if T=TLDS[I] then begin Result:=True; Exit; end; end;

function HU(const S: string): Boolean;
var I: Integer;
begin Result:=False; for I:=1 to Length(S) do if CharInSet(S[I],['A'..'Z']) then begin Result:=True; Exit; end; end;

function GTLD(const Lo: string): string;
var I: Integer;
begin I:=Length(Lo); while (I>0) and (Lo[I]<>'.') do Dec(I); if I>0 then Result:=Copy(Lo,I+1,Length(Lo)-I) else Result:=''; end;

function ClassifyString(const S: string): TStringCategory;
var Lo: string; I,Dots,Colons,Len,Seg: Integer; Alpha,AllHex: Boolean;
begin
  Result:=scOther; Lo:=LowerCase(S); Len:=Length(Lo); if Len<4 then Exit;
  if (Pos('http://',Lo)=1) or (Pos('https://',Lo)=1) or (Pos('ftp://',Lo)=1) or (Pos('ws://',Lo)=1) or (Pos('wss://',Lo)=1) then begin Result:=scURL; Exit; end;
  Dots:=0; Alpha:=False;
  for I:=1 to Len do if Lo[I]='.' then Inc(Dots) else if not CharInSet(Lo[I],['0'..'9']) then begin Alpha:=True; Break; end;
  if (not Alpha) and (Dots=3) and (Len>=7) and (Len<=15) then begin Result:=scIPv4; Exit; end;
  Colons:=0; AllHex:=True;
  for I:=1 to Len do if Lo[I]=':' then Inc(Colons) else if not CharInSet(Lo[I],['0'..'9','a'..'f']) then begin AllHex:=False; Break; end;
  if AllHex and (Colons>=2) and (Len>=6) then begin Result:=scIPv6; Exit; end;
  if SW(Lo,BAD_PRE) then Exit; if EW(Lo,BAD_SUF) then Exit;
  if HU(S) then Exit; if CharInSet(S[1],['.','0'..'9']) then Exit;
  Dots:=0; Alpha:=False;
  for I:=1 to Len do if Lo[I]='.' then Inc(Dots) else if CharInSet(Lo[I],['a'..'z']) then Alpha:=True
    else if CharInSet(Lo[I],['0'..'9']) then else if Lo[I]='-' then else Exit;
  if (Dots<1) or (not Alpha) or (Len<4) then Exit;
  Seg:=0; for I:=1 to Len do if Lo[I]='.' then begin if Seg<2 then Exit; Seg:=0; end else Inc(Seg);
  if Seg<2 then Exit; if not VTLD(GTLD(Lo)) then Exit;
  if Dots>=2 then Result:=scDomain else Result:=scHostname;
end;

function CategoryLabel(Cat: TStringCategory): string;
begin case Cat of scURL:Result:='URL'; scDomain:Result:='Domain'; scIPv4:Result:='IPv4'; scIPv6:Result:='IPv6'; scHostname:Result:='Hostname'; else Result:='Other'; end; end;

function ProtectToStr(P: DWORD): string;
begin
  if (P and PAGE_EXECUTE_READWRITE)<>0 then Result:='RWX'
  else if (P and PAGE_EXECUTE_READ)<>0 then Result:='RX'
  else if (P and PAGE_READWRITE)<>0 then Result:='RW'
  else if (P and PAGE_READONLY)<>0 then Result:='R'
  else if (P and PAGE_WRITECOPY)<>0 then Result:='WC'
  else if (P and PAGE_EXECUTE)<>0 then Result:='X'
  else Result:=Format('0x%x',[P]);
end;

function IsReadable(P: DWORD): Boolean;
begin Result:=(P and (PAGE_READONLY or PAGE_READWRITE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_WRITECOPY or PAGE_EXECUTE_WRITECOPY))<>0; end;

procedure AddNet(var R: TExtractedStringArray; const S: string; A: NativeUInt);
var C: TStringCategory; X: Integer;
begin C:=ClassifyString(S); if C=scOther then Exit; X:=Length(R); SetLength(R,X+1); R[X].Value:=S; R[X].Category:=C; R[X].Address:=A; end;

procedure AddRaw(var R: TRawMemStringArray; const S,Pr,Enc: string; A: NativeUInt);
var X: Integer;
begin X:=Length(R); SetLength(R,X+1); R[X].Value:=S; R[X].Address:=A; R[X].Len:=Length(S); R[X].Protect:=Pr; R[X].Encoding:=Enc; end;

procedure ExASCII(Buf: PByte; BL,Base: NativeUInt; ML: Integer; var NR: TExtractedStringArray; var RR: TRawMemStringArray; const Pr: string; DN,DR: Boolean);
var I,RS,RL: NativeUInt; P: PByte; S: string;
begin
  RS:=0; I:=0; P:=Buf;
  while I<BL do begin
    if IsPrint(P^) then begin if RS=0 then RS:=I+1; end
    else begin if RS>0 then begin RL:=I-(RS-1); if Integer(RL)>=ML then begin SetString(S,PAnsiChar(Buf+(RS-1)),RL);
      if DN then AddNet(NR,S,Base+(RS-1)); if DR then AddRaw(RR,S,Pr,'ASCII',Base+(RS-1)); end; RS:=0; end; end;
    Inc(P); Inc(I);
  end;
  if RS>0 then begin RL:=BL-(RS-1); if Integer(RL)>=ML then begin SetString(S,PAnsiChar(Buf+(RS-1)),RL);
    if DN then AddNet(NR,S,Base+(RS-1)); if DR then AddRaw(RR,S,Pr,'ASCII',Base+(RS-1)); end; end;
end;

procedure ExUTF16(Buf: PByte; BL,Base: NativeUInt; ML: Integer; var NR: TExtractedStringArray; var RR: TRawMemStringArray; const Pr: string; DN,DR: Boolean);
var I,RS,CC: NativeUInt; W: Word; S: string; J: NativeUInt;
begin
  if BL<2 then Exit; RS:=0; CC:=0; I:=0;
  while I+1<BL do begin W:=PWord(Buf+I)^;
    if (W>=32) and (W<=126) then begin if RS=0 then begin RS:=I; CC:=0; end; Inc(CC); end
    else begin if (RS>0) and (Integer(CC)>=ML) then begin SetLength(S,CC);
      for J:=0 to CC-1 do S[J+1]:=Char(PWord(Buf+RS+J*2)^);
      if DN then AddNet(NR,S,Base+RS); if DR then AddRaw(RR,S,Pr,'UTF16',Base+RS); end; RS:=0; CC:=0; end;
    Inc(I,2);
  end;
  if (RS>0) and (Integer(CC)>=ML) then begin SetLength(S,CC);
    for J:=0 to CC-1 do S[J+1]:=Char(PWord(Buf+RS+J*2)^);
    if DN then AddNet(NR,S,Base+RS); if DR then AddRaw(RR,S,Pr,'UTF16',Base+RS); end;
end;

procedure DoScan(PID: DWORD; ML: Integer; MR: NativeUInt; var NR: TExtractedStringArray; var RR: TRawMemStringArray; DN,DR: Boolean);
var hP: THandle; Ad: NativeUInt; MBI: TMemoryBasicInformation; Buf: PByte; BR,RS: NativeUInt; Pr: string;
begin
  hP:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hP=0 then Exit;
  try Ad:=0;
    while VirtualQueryEx(hP,Pointer(Ad),MBI,SizeOf(MBI))=SizeOf(MBI) do begin
      if (MBI.State=MEM_COMMIT) and IsReadable(MBI.Protect) and ((MBI.Protect and PAGE_GUARD)=0) then begin
        RS:=MBI.RegionSize; if RS>MR then RS:=MR; Pr:=ProtectToStr(MBI.Protect); GetMem(Buf,RS);
        try BR:=0; if ReadProcessMemory(hP,MBI.BaseAddress,Buf,RS,BR) and (BR>0) then begin
          ExASCII(Buf,BR,NativeUInt(MBI.BaseAddress),ML,NR,RR,Pr,DN,DR);
          ExUTF16(Buf,BR,NativeUInt(MBI.BaseAddress),ML,NR,RR,Pr,DN,DR); end;
        finally FreeMem(Buf); end;
      end;
      Ad:=NativeUInt(MBI.BaseAddress)+MBI.RegionSize; if Ad=0 then Break;
    end;
  finally CloseHandle(hP); end;
end;

function ScanProcessMemory(PID: DWORD; MinLen: Integer; MaxReg: NativeUInt): TExtractedStringArray;
var D: TRawMemStringArray;
begin SetLength(Result,0); SetLength(D,0); DoScan(PID,MinLen,MaxReg,Result,D,True,False); end;

function ScanProcessMemoryFull(PID: DWORD; MinLen: Integer; MaxReg: NativeUInt): TRawMemStringArray;
var D: TExtractedStringArray;
begin SetLength(Result,0); SetLength(D,0); DoScan(PID,MinLen,MaxReg,D,Result,False,True); end;

end.
