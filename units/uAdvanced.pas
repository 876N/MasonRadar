unit uAdvanced;

interface

uses
  Winapi.Windows, Winapi.TlHelp32, System.SysUtils, System.Math, System.Classes;

const
  PM_TH32CS_SNAPMODULE32 = $00000010;

type
  THookInfo = record
    DLLName, APIName, Bytes, HookType: string;
    Address: NativeUInt;
    Hooked: Boolean;
  end;
  THookInfoArray = array of THookInfo;

  TXorResult = record
    KeyHex: string; Address: NativeUInt; Decoded: string; Key: Byte;
  end;
  TXorResultArray = array of TXorResult;

  TEntropyBlock = record
    Address: NativeUInt; Size: NativeUInt; Entropy: Double; Protect: string;
  end;
  TEntropyBlockArray = array of TEntropyBlock;

  TSuspiciousModule = record
    Name, Path, Reason: string; Base: NativeUInt; Size: DWORD;
  end;
  TSuspiciousModuleArray = array of TSuspiciousModule;

  TIATEntry = record
    DLLName, FuncName: string;
  end;
  TIATEntryArray = array of TIATEntry;

  TFilePathEntry = record
    Value: string; Address: NativeUInt; PathType: string;
  end;
  TFilePathEntryArray = array of TFilePathEntry;

  TPayloadInfo = record
    Address: NativeUInt;
    Size: DWORD;
    Protect: string;
    PEType: string;
    Data: TBytes;
  end;
  TPayloadInfoArray = array of TPayloadInfo;

function DetectHooks(PID: DWORD): THookInfoArray;
function ScanXorStrings(PID: DWORD; MaxReg: NativeUInt = 2*1024*1024): TXorResultArray;
function ScanEntropy(PID: DWORD; BlockSize: Integer = 4096; Threshold: Double = 7.2): TEntropyBlockArray;
function DetectSuspiciousModules(PID: DWORD): TSuspiciousModuleArray;
function ReadIATImports(PID: DWORD): TIATEntryArray;
function ScanFilePaths(PID: DWORD; MaxReg: NativeUInt = 4*1024*1024): TFilePathEntryArray;
function ScanPayloads(PID: DWORD; MaxReg: NativeUInt = 4*1024*1024): TPayloadInfoArray;
function ExportPayload(const PI: TPayloadInfo; const FileName: string): Boolean;

implementation

function ProtStr(P: DWORD): string;
begin
  if (P and PAGE_EXECUTE_READWRITE)<>0 then Result:='RWX'
  else if (P and PAGE_EXECUTE_READ)<>0 then Result:='RX'
  else if (P and PAGE_READWRITE)<>0 then Result:='RW'
  else if (P and PAGE_READONLY)<>0 then Result:='R'
  else Result:=Format('0x%x',[P]);
end;

function BytesToHex(B: PByte; Count: Integer): string;
var I: Integer;
begin
  Result:='';
  for I:=0 to Count-1 do begin
    if I>0 then Result:=Result+' ';
    Result:=Result+IntToHex((B+I)^,2);
  end;
end;

function IsHookOpcode(B: PByte): string;
begin
  Result:='';
  if B^=$E9 then Result:='JMP rel32'
  else if B^=$EB then Result:='JMP rel8'
  else if (B^=$FF) and ((B+1)^=$25) then Result:='JMP [addr]'
  else if (B^=$68) and ((B+5)^=$C3) then Result:='PUSH+RET'
  else if (B^=$B8) and ((B+5)^=$FF) and ((B+6)^=$E0) then Result:='MOV EAX+JMP EAX';
end;

function IsReadable(P: DWORD): Boolean;
begin Result:=(P and (PAGE_READONLY or PAGE_READWRITE or PAGE_EXECUTE_READ or
  PAGE_EXECUTE_READWRITE or PAGE_WRITECOPY or PAGE_EXECUTE_WRITECOPY))<>0; end;

type
  TAPIEntry = record D,F: string; end;
const
  APIS: array[0..24] of TAPIEntry = (
    (D:'kernel32.dll'; F:'VirtualAlloc'),
    (D:'kernel32.dll'; F:'VirtualProtect'),
    (D:'kernel32.dll'; F:'CreateFileW'),
    (D:'kernel32.dll'; F:'WriteFile'),
    (D:'kernel32.dll'; F:'ReadFile'),
    (D:'kernel32.dll'; F:'CreateProcessW'),
    (D:'kernel32.dll'; F:'LoadLibraryW'),
    (D:'kernel32.dll'; F:'GetProcAddress'),
    (D:'kernel32.dll'; F:'WriteProcessMemory'),
    (D:'kernel32.dll'; F:'IsDebuggerPresent'),
    (D:'kernel32.dll'; F:'GetTickCount'),
    (D:'kernel32.dll'; F:'Sleep'),
    (D:'ntdll.dll'; F:'NtCreateFile'),
    (D:'ntdll.dll'; F:'NtWriteFile'),
    (D:'ntdll.dll'; F:'NtAllocateVirtualMemory'),
    (D:'ntdll.dll'; F:'NtProtectVirtualMemory'),
    (D:'ntdll.dll'; F:'NtQuerySystemInformation'),
    (D:'ntdll.dll'; F:'NtQueryInformationProcess'),
    (D:'ws2_32.dll'; F:'send'),
    (D:'ws2_32.dll'; F:'recv'),
    (D:'ws2_32.dll'; F:'connect'),
    (D:'ws2_32.dll'; F:'WSASend'),
    (D:'ws2_32.dll'; F:'WSARecv'),
    (D:'wininet.dll'; F:'InternetOpenA'),
    (D:'wininet.dll'; F:'HttpSendRequestA'));

function DetectHooks(PID: DWORD): THookInfoArray;
var
  hProc,hMod: THandle; pFunc: Pointer; Buf: array[0..15] of Byte;
  BR: NativeUInt; I,X: Integer; HT: string;
begin
  SetLength(Result,0);
  hProc:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hProc=0 then Exit;
  try
    for I:=Low(APIS) to High(APIS) do begin
      hMod:=GetModuleHandle(PChar(APIS[I].D));
      if hMod=0 then Continue;
      pFunc:=GetProcAddress(hMod,PAnsiChar(AnsiString(APIS[I].F)));
      if pFunc=nil then Continue;
      FillChar(Buf,SizeOf(Buf),0); BR:=0;
      if not ReadProcessMemory(hProc,pFunc,@Buf,16,BR) then Continue;
      if BR<6 then Continue;
      HT:=IsHookOpcode(@Buf[0]);
      X:=Length(Result); SetLength(Result,X+1);
      Result[X].DLLName:=APIS[I].D; Result[X].APIName:=APIS[I].F;
      Result[X].Address:=NativeUInt(pFunc);
      Result[X].Bytes:=BytesToHex(@Buf[0],12);
      Result[X].Hooked:=(HT<>'');
      if HT<>'' then Result[X].HookType:=HT else Result[X].HookType:='Clean';
    end;
  finally CloseHandle(hProc); end;
end;

function ScanXorStrings(PID: DWORD; MaxReg: NativeUInt): TXorResultArray;
var
  hProc: THandle; Addr: NativeUInt; MBI: TMemoryBasicInformation;
  Buf: PByte; BR,RS,I,J,X: NativeUInt; Key: Byte; C: AnsiChar; S: string;
begin
  SetLength(Result,0);
  hProc:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hProc=0 then Exit;
  try Addr:=0;
    while VirtualQueryEx(hProc,Pointer(Addr),MBI,SizeOf(MBI))=SizeOf(MBI) do begin
      if (MBI.State=MEM_COMMIT) and IsReadable(MBI.Protect) and ((MBI.Protect and PAGE_GUARD)=0) then begin
        RS:=MBI.RegionSize; if RS>MaxReg then RS:=MaxReg;
        GetMem(Buf,RS);
        try BR:=0;
          if ReadProcessMemory(hProc,MBI.BaseAddress,Buf,RS,BR) and (BR>7) then begin
            I:=0;
            while I<BR-7 do begin
              Key:=Buf[I] xor Ord('h');
              if (Key>=1) and (Key<=$FE) then begin
                if ((Buf[I+1] xor Key)=Ord('t')) and ((Buf[I+2] xor Key)=Ord('t')) and
                   ((Buf[I+3] xor Key)=Ord('p')) then begin
                  S:=''; J:=I;
                  while J<BR do begin C:=AnsiChar(Buf[J] xor Key);
                    if (Ord(C)<32) or (Ord(C)>126) then Break;
                    S:=S+Char(C); Inc(J); end;
                  if Length(S)>=10 then begin X:=Length(Result);
                    if X<5000 then begin SetLength(Result,X+1);
                      Result[X].Key:=Key; Result[X].KeyHex:='0x'+IntToHex(Key,2);
                      Result[X].Address:=NativeUInt(MBI.BaseAddress)+I;
                      Result[X].Decoded:=S; end; end;
                  I:=J; Continue;
                end;
              end;
              Inc(I);
            end;
          end;
        finally FreeMem(Buf); end;
      end;
      Addr:=NativeUInt(MBI.BaseAddress)+MBI.RegionSize; if Addr=0 then Break;
    end;
  finally CloseHandle(hProc); end;
end;

function CalcEntropy(Buf: PByte; Len: Integer): Double;
var Freq: array[0..255] of Integer; I: Integer; P: Double;
begin
  Result:=0; if Len=0 then Exit;
  FillChar(Freq,SizeOf(Freq),0);
  for I:=0 to Len-1 do Inc(Freq[(Buf+I)^]);
  for I:=0 to 255 do begin if Freq[I]=0 then Continue;
    P:=Freq[I]/Len; Result:=Result-P*Log2(P); end;
end;

function ScanEntropy(PID: DWORD; BlockSize: Integer; Threshold: Double): TEntropyBlockArray;
var
  hProc: THandle; Addr: NativeUInt; MBI: TMemoryBasicInformation;
  Buf: PByte; BR,RS,Off: NativeUInt; E: Double; X,CS: Integer; Pr: string;
begin
  SetLength(Result,0);
  hProc:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hProc=0 then Exit;
  try Addr:=0;
    while VirtualQueryEx(hProc,Pointer(Addr),MBI,SizeOf(MBI))=SizeOf(MBI) do begin
      if (MBI.State=MEM_COMMIT) and IsReadable(MBI.Protect) and ((MBI.Protect and PAGE_GUARD)=0) then begin
        RS:=MBI.RegionSize; if RS>4*1024*1024 then RS:=4*1024*1024;
        Pr:=ProtStr(MBI.Protect); GetMem(Buf,RS);
        try BR:=0;
          if ReadProcessMemory(hProc,MBI.BaseAddress,Buf,RS,BR) and (BR>0) then begin
            Off:=0;
            while Off+NativeUInt(BlockSize)<=BR do begin
              CS:=BlockSize; E:=CalcEntropy(Buf+Off,CS);
              if E>=Threshold then begin X:=Length(Result);
                if X<2000 then begin SetLength(Result,X+1);
                  Result[X].Address:=NativeUInt(MBI.BaseAddress)+Off;
                  Result[X].Size:=NativeUInt(CS); Result[X].Entropy:=E;
                  Result[X].Protect:=Pr; end; end;
              Off:=Off+NativeUInt(BlockSize);
            end;
          end;
        finally FreeMem(Buf); end;
      end;
      Addr:=NativeUInt(MBI.BaseAddress)+MBI.RegionSize; if Addr=0 then Break;
    end;
  finally CloseHandle(hProc); end;
end;

const
  SUS_NAMES: array[0..19] of string = (
    'sbiedll','snxhk','vmcheck','vboxhook','cuckoomon','pstorec','dir_watch',
    'api_log','dbghelp','sysinternals','wireshark','fiddler','procmon',
    'apimonitor','hookshark','detourslib','mhook','easyhook','frida','injector');

function DetectSuspiciousModules(PID: DWORD): TSuspiciousModuleArray;
var Snap: THandle; ME: TModuleEntry32; Lo: string; I,X: Integer;
begin
  SetLength(Result,0);
  Snap:=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or PM_TH32CS_SNAPMODULE32,PID);
  if Snap=INVALID_HANDLE_VALUE then Exit;
  try ME.dwSize:=SizeOf(ME);
    if not Module32First(Snap,ME) then Exit;
    repeat
      Lo:=LowerCase(string(ME.szModule));
      for I:=Low(SUS_NAMES) to High(SUS_NAMES) do begin
        if Pos(SUS_NAMES[I],Lo)>0 then begin
          X:=Length(Result); SetLength(Result,X+1);
          Result[X].Name:=string(ME.szModule); Result[X].Path:=string(ME.szExePath);
          Result[X].Base:=NativeUInt(ME.modBaseAddr); Result[X].Size:=ME.modBaseSize;
          Result[X].Reason:='Matches: '+SUS_NAMES[I]; Break;
        end;
      end;
    until not Module32Next(Snap,ME);
  finally CloseHandle(Snap); end;
end;

function ReadIATImports(PID: DWORD): TIATEntryArray;
var
  Snap: THandle; ME: TModuleEntry32; Lo: string; X: Integer;
begin
  SetLength(Result,0);
  Snap:=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or PM_TH32CS_SNAPMODULE32,PID);
  if Snap=INVALID_HANDLE_VALUE then Exit;
  try ME.dwSize:=SizeOf(ME);
    if not Module32First(Snap,ME) then Exit;
    repeat
      Lo:=LowerCase(string(ME.szModule));
      X:=Length(Result); SetLength(Result,X+1);
      Result[X].DLLName:=string(ME.szModule);
      Result[X].FuncName:=string(ME.szExePath);
    until not Module32Next(Snap,ME);
  finally CloseHandle(Snap); end;
end;

function IsPrint(B: Byte): Boolean; inline;
begin Result:=(B>=32) and (B<=126); end;

function ClassifyPath(const S: string): string;
var Lo: string;
begin
  Lo:=LowerCase(S);
  if (Pos('hkey_',Lo)>0) or (Pos('hklm\',Lo)>0) or (Pos('hkcu\',Lo)>0) then begin Result:='Registry'; Exit; end;
  if (Length(S)>=3) and CharInSet(S[1],['A'..'Z','a'..'z']) and (S[2]=':') and (S[3]='\') then begin Result:='FilePath'; Exit; end;
  if (Length(S)>=2) and (S[1]='\') and (S[2]='\') then begin Result:='UNC'; Exit; end;
  if (Pos('.tmp',Lo)>0) or (Pos('.dat',Lo)>0) or (Pos('.log',Lo)>0) or
     (Pos('.ini',Lo)>0) or (Pos('.cfg',Lo)>0) or (Pos('.config',Lo)>0) then begin Result:='ConfigFile'; Exit; end;
  Result:='';
end;

function ScanFilePaths(PID: DWORD; MaxReg: NativeUInt): TFilePathEntryArray;
var
  hProc: THandle; Addr: NativeUInt; MBI: TMemoryBasicInformation;
  Buf: PByte; BR,RS,I,RunStart,RL: NativeUInt; P: PByte; S,PT: string; X: Integer;
begin
  SetLength(Result,0);
  hProc:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hProc=0 then Exit;
  try Addr:=0;
    while VirtualQueryEx(hProc,Pointer(Addr),MBI,SizeOf(MBI))=SizeOf(MBI) do begin
      if (MBI.State=MEM_COMMIT) and IsReadable(MBI.Protect) and ((MBI.Protect and PAGE_GUARD)=0) then begin
        RS:=MBI.RegionSize; if RS>MaxReg then RS:=MaxReg;
        GetMem(Buf,RS);
        try BR:=0;
          if ReadProcessMemory(hProc,MBI.BaseAddress,Buf,RS,BR) and (BR>4) then begin
            RunStart:=0; I:=0; P:=Buf;
            while I<BR do begin
              if IsPrint(P^) then begin if RunStart=0 then RunStart:=I+1; end
              else begin
                if RunStart>0 then begin RL:=I-(RunStart-1);
                  if RL>=6 then begin
                    SetString(S,PAnsiChar(Buf+(RunStart-1)),RL);
                    PT:=ClassifyPath(S);
                    if PT<>'' then begin X:=Length(Result);
                      if X<10000 then begin SetLength(Result,X+1);
                        Result[X].Value:=S; Result[X].Address:=NativeUInt(MBI.BaseAddress)+(RunStart-1);
                        Result[X].PathType:=PT; end; end;
                  end; RunStart:=0;
                end;
              end;
              Inc(P); Inc(I);
            end;
          end;
        finally FreeMem(Buf); end;
      end;
      Addr:=NativeUInt(MBI.BaseAddress)+MBI.RegionSize; if Addr=0 then Break;
    end;
  finally CloseHandle(hProc); end;
end;

function ScanPayloads(PID: DWORD; MaxReg: NativeUInt): TPayloadInfoArray;
var
  hProc: THandle; Addr: NativeUInt; MBI: TMemoryBasicInformation;
  Buf: PByte; BR,RS,I: NativeUInt; X: Integer;
  ELfanew: DWORD; PESig: DWORD; Machine: Word;
  PayloadSize: DWORD; Pr,PETypeStr: string;
begin
  SetLength(Result,0);
  hProc:=OpenProcess(PROCESS_VM_READ or PROCESS_QUERY_INFORMATION,False,PID);
  if hProc=0 then Exit;
  try Addr:=0;
    while VirtualQueryEx(hProc,Pointer(Addr),MBI,SizeOf(MBI))=SizeOf(MBI) do begin
      if (MBI.State=MEM_COMMIT) and IsReadable(MBI.Protect) and ((MBI.Protect and PAGE_GUARD)=0) then begin
        RS:=MBI.RegionSize; if RS>MaxReg then RS:=MaxReg;
        Pr:=ProtStr(MBI.Protect); GetMem(Buf,RS);
        try BR:=0;
          if ReadProcessMemory(hProc,MBI.BaseAddress,Buf,RS,BR) and (BR>512) then begin
            I:=0;
            while I<BR-256 do begin
              if (Buf[I]=$4D) and (Buf[I+1]=$5A) then begin
                if I+64>BR then begin Inc(I,2); Continue; end;
                ELfanew:=PDWORD(Buf+I+$3C)^;
                if (ELfanew<$1000) and (I+ELfanew+6<BR) then begin
                  PESig:=PDWORD(Buf+I+ELfanew)^;
                  if PESig=$00004550 then begin
                    Machine:=PWord(Buf+I+ELfanew+4)^;
                    if Machine=$014C then PETypeStr:='PE32 (x86)'
                    else if Machine=$8664 then PETypeStr:='PE32+ (x64)'
                    else PETypeStr:='PE (Unknown)';
                    PayloadSize:=DWORD(BR-I);
                    if PayloadSize>1024*1024 then PayloadSize:=1024*1024;
                    X:=Length(Result);
                    if X<100 then begin
                      SetLength(Result,X+1);
                      Result[X].Address:=NativeUInt(MBI.BaseAddress)+I;
                      Result[X].Size:=PayloadSize;
                      Result[X].Protect:=Pr;
                      Result[X].PEType:=PETypeStr;
                      SetLength(Result[X].Data,PayloadSize);
                      Move((Buf+I)^,Result[X].Data[0],PayloadSize);
                    end;
                    I:=I+PayloadSize;
                    Continue;
                  end;
                end;
              end;
              Inc(I);
            end;
          end;
        finally FreeMem(Buf); end;
      end;
      Addr:=NativeUInt(MBI.BaseAddress)+MBI.RegionSize; if Addr=0 then Break;
    end;
  finally CloseHandle(hProc); end;
end;

function ExportPayload(const PI: TPayloadInfo; const FileName: string): Boolean;
var FS: TFileStream;
begin
  Result:=False;
  if Length(PI.Data)=0 then Exit;
  try
    FS:=TFileStream.Create(FileName,fmCreate);
    try FS.WriteBuffer(PI.Data[0],Length(PI.Data)); Result:=True;
    finally FS.Free; end;
  except Result:=False; end;
end;

end.
