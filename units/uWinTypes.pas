unit uWinTypes;

interface

uses
  Winapi.Windows, System.SysUtils;

const
  PM_AF_INET = 2;
  MIB_TCP_STATE_CLOSED = 1; MIB_TCP_STATE_LISTEN = 2; MIB_TCP_STATE_SYN_SENT = 3;
  MIB_TCP_STATE_SYN_RCVD = 4; MIB_TCP_STATE_ESTAB = 5; MIB_TCP_STATE_FIN_WAIT1 = 6;
  MIB_TCP_STATE_FIN_WAIT2 = 7; MIB_TCP_STATE_CLOSE_WAIT = 8; MIB_TCP_STATE_CLOSING = 9;
  MIB_TCP_STATE_LAST_ACK = 10; MIB_TCP_STATE_TIME_WAIT = 11; MIB_TCP_STATE_DELETE_TCB = 12;
  TCP_TABLE_OWNER_PID_ALL = 5; UDP_TABLE_OWNER_PID = 1;
  SECURITY_MANDATORY_LOW_RID = $00001000; SE_GROUP_INTEGRITY = $00000020;
  PM_TokenIntegrityLevel = 25;
  SECURITY_MANDATORY_LABEL_AUTHORITY: TSIDIdentifierAuthority = (Value:(0,0,0,0,0,16));
  PM_CREATE_SUSPENDED = $04; PM_CREATE_NEW_CONSOLE = $10; DISABLE_MAX_PRIVILEGE = $04;

type
  MIB_TCPROW_OWNER_PID = record dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid: DWORD; end;
  PMIB_TCPROW_OWNER_PID = ^MIB_TCPROW_OWNER_PID;
  MIB_TCPTABLE_OWNER_PID = record dwNumEntries: DWORD; Table: array[0..0] of MIB_TCPROW_OWNER_PID; end;
  PMIB_TCPTABLE_OWNER_PID = ^MIB_TCPTABLE_OWNER_PID;
  MIB_UDPROW_OWNER_PID = record dwLocalAddr, dwLocalPort, dwOwningPid: DWORD; end;
  PMIB_UDPROW_OWNER_PID = ^MIB_UDPROW_OWNER_PID;
  MIB_UDPTABLE_OWNER_PID = record dwNumEntries: DWORD; Table: array[0..0] of MIB_UDPROW_OWNER_PID; end;
  PMIB_UDPTABLE_OWNER_PID = ^MIB_UDPTABLE_OWNER_PID;
  PM_SID_AND_ATTRIBUTES = record Sid: PSID; Attributes: DWORD; end;
  PM_TOKEN_MANDATORY_LABEL = record MandatoryLabel: PM_SID_AND_ATTRIBUTES; end;

function GetExtendedTcpTable(p: Pointer; var s: DWORD; b: BOOL; af: ULONG; tc: DWORD; r: ULONG): DWORD; stdcall;
function GetExtendedUdpTable(p: Pointer; var s: DWORD; b: BOOL; af: ULONG; tc: DWORD; r: ULONG): DWORD; stdcall;
function PM_CreateRestrictedToken(h: THandle; f,d: DWORD; sd: Pointer; dp: DWORD; pd: Pointer; rs: DWORD; sr: Pointer; var n: THandle): BOOL; stdcall;
function PM_CreateProcessAsUser(h: THandle; an,cl: PChar; pa,ta: PSecurityAttributes; ih: BOOL; cf: DWORD; e: Pointer; cd: PChar; const si: TStartupInfo; var pi: TProcessInformation): BOOL; stdcall;
function PM_SetTokenInformation(h: THandle; tc: DWORD; ti: Pointer; tl: DWORD): BOOL; stdcall;
function DwordToIPv4(A: DWORD): string;
function NtoHs(N: Word): Word;
function TcpStateToString(S: DWORD): string;

implementation

function GetExtendedTcpTable; external 'iphlpapi.dll';
function GetExtendedUdpTable; external 'iphlpapi.dll';
function PM_CreateRestrictedToken; external 'advapi32.dll' name 'CreateRestrictedToken';
function PM_SetTokenInformation; external 'advapi32.dll' name 'SetTokenInformation';
function PM_CreateProcessAsUser; external 'advapi32.dll' name {$IFDEF UNICODE}'CreateProcessAsUserW'{$ELSE}'CreateProcessAsUserA'{$ENDIF};

function DwordToIPv4(A: DWORD): string;
begin Result := Format('%d.%d.%d.%d',[A and $FF,(A shr 8) and $FF,(A shr 16) and $FF,(A shr 24) and $FF]); end;
function NtoHs(N: Word): Word; begin Result := Swap(N); end;
function TcpStateToString(S: DWORD): string;
begin
  case S of 1: Result:='CLOSED'; 2: Result:='LISTEN'; 3: Result:='SYN_SENT'; 4: Result:='SYN_RCVD';
    5: Result:='ESTABLISHED'; 6: Result:='FIN_WAIT1'; 7: Result:='FIN_WAIT2'; 8: Result:='CLOSE_WAIT';
    9: Result:='CLOSING'; 10: Result:='LAST_ACK'; 11: Result:='TIME_WAIT'; 12: Result:='DELETE_TCB';
  else Result:=Format('(%d)',[S]); end;
end;

end.
