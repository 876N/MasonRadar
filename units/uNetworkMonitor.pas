unit uNetworkMonitor;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, uWinTypes;

type
  TNetConnection = record
    Protocol, LocalAddr, RemoteAddr, State, Detection: string;
    LocalPort, RemotePort: Word;
  end;
  TNetConnectionArray = array of TNetConnection;

function GetConnectionsForPID(PID: DWORD): TNetConnectionArray;

implementation

function Guess(Port: Word; const P: string): string;
begin
  case Port of
    20,21: Result:='FTP'; 22: Result:='SSH'; 23: Result:='Telnet'; 25: Result:='SMTP';
    53: Result:='DNS'; 80: Result:='HTTP'; 110: Result:='POP3'; 143: Result:='IMAP';
    443: Result:='HTTPS/WSS'; 445: Result:='SMB'; 993: Result:='IMAPS'; 995: Result:='POP3S';
    1080: Result:='SOCKS'; 1433: Result:='MSSQL'; 3306: Result:='MySQL'; 3389: Result:='RDP';
    5432: Result:='PostgreSQL'; 5900: Result:='VNC'; 8080: Result:='HTTP-Alt'; 8443: Result:='HTTPS-Alt';
  else Result := P; end;
end;

procedure DoTcp(PID: DWORD; var C: TNetConnectionArray);
var S: DWORD; B: PByte; T: PMIB_TCPTABLE_OWNER_PID; R: PMIB_TCPROW_OWNER_PID; I,X: Integer;
begin
  S:=0; GetExtendedTcpTable(nil,S,True,PM_AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
  if S=0 then Exit; GetMem(B,S);
  try if GetExtendedTcpTable(B,S,True,PM_AF_INET,TCP_TABLE_OWNER_PID_ALL,0)<>0 then Exit;
    T:=PMIB_TCPTABLE_OWNER_PID(B);
    for I:=0 to Integer(T^.dwNumEntries)-1 do begin R:=@T^.Table[I]; if R^.dwOwningPid<>PID then Continue;
      X:=Length(C); SetLength(C,X+1); C[X].Protocol:='TCP'; C[X].LocalAddr:=DwordToIPv4(R^.dwLocalAddr);
      C[X].LocalPort:=NtoHs(Word(R^.dwLocalPort)); C[X].RemoteAddr:=DwordToIPv4(R^.dwRemoteAddr);
      C[X].RemotePort:=NtoHs(Word(R^.dwRemotePort)); C[X].State:=TcpStateToString(R^.dwState);
      C[X].Detection:=Guess(C[X].RemotePort,'TCP');
      if C[X].Detection='TCP' then C[X].Detection:=Guess(C[X].LocalPort,'TCP');
    end;
  finally FreeMem(B); end;
end;

procedure DoUdp(PID: DWORD; var C: TNetConnectionArray);
var S: DWORD; B: PByte; T: PMIB_UDPTABLE_OWNER_PID; R: PMIB_UDPROW_OWNER_PID; I,X: Integer;
begin
  S:=0; GetExtendedUdpTable(nil,S,True,PM_AF_INET,UDP_TABLE_OWNER_PID,0);
  if S=0 then Exit; GetMem(B,S);
  try if GetExtendedUdpTable(B,S,True,PM_AF_INET,UDP_TABLE_OWNER_PID,0)<>0 then Exit;
    T:=PMIB_UDPTABLE_OWNER_PID(B);
    for I:=0 to Integer(T^.dwNumEntries)-1 do begin R:=@T^.Table[I]; if R^.dwOwningPid<>PID then Continue;
      X:=Length(C); SetLength(C,X+1); C[X].Protocol:='UDP'; C[X].LocalAddr:=DwordToIPv4(R^.dwLocalAddr);
      C[X].LocalPort:=NtoHs(Word(R^.dwLocalPort)); C[X].RemoteAddr:='*'; C[X].RemotePort:=0; C[X].State:='';
      C[X].Detection:=Guess(C[X].LocalPort,'UDP');
    end;
  finally FreeMem(B); end;
end;

function GetConnectionsForPID(PID: DWORD): TNetConnectionArray;
begin SetLength(Result,0); DoTcp(PID,Result); DoUdp(PID,Result); end;

end.
