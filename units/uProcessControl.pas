unit uProcessControl;

interface

uses
  Winapi.Windows, System.SysUtils, uWinTypes;

type
  TProcessInfo = record
    ExePath: string; PID: DWORD; hProcess, hThread: THandle;
    IsRunning, UsedRestricted: Boolean; ErrorMsg: string;
  end;

function  LaunchProcess(const APath: string; out Info: TProcessInfo): Boolean;
function  IsProcessAlive(var Info: TProcessInfo): Boolean;
procedure KillProcess(var Info: TProcessInfo);
procedure CleanupProcess(var Info: TProcessInfo);

implementation

function LaunchNormal(const P: string; out PI: TProcessInformation; out E: string): Boolean;
var SI: TStartupInfo; Cmd: string;
begin
  FillChar(SI,SizeOf(SI),0); SI.cb := SizeOf(SI); FillChar(PI,SizeOf(PI),0); Cmd := '"'+P+'"';
  Result := CreateProcess(nil,PChar(Cmd),nil,nil,False,CREATE_NEW_CONSOLE,nil,nil,SI,PI);
  if not Result then E := SysErrorMessage(GetLastError);
end;

function LaunchProcess(const APath: string; out Info: TProcessInfo): Boolean;
var PI: TProcessInformation; E: string;
begin
  Info.ExePath := APath; Info.PID := 0; Info.hProcess := 0; Info.hThread := 0;
  Info.IsRunning := False; Info.UsedRestricted := False; Info.ErrorMsg := '';
  Result := LaunchNormal(APath,PI,E);
  if Result then begin
    Info.PID := PI.dwProcessId; Info.hProcess := PI.hProcess;
    Info.hThread := PI.hThread; Info.IsRunning := True;
    Info.UsedRestricted := False;
  end else begin
    Info.IsRunning := False; Info.ErrorMsg := E;
  end;
end;

function IsProcessAlive(var Info: TProcessInfo): Boolean;
var C: DWORD;
begin Result := False; if Info.hProcess=0 then Exit;
  if GetExitCodeProcess(Info.hProcess,C) then Result := (C=STILL_ACTIVE); Info.IsRunning := Result; end;

procedure KillProcess(var Info: TProcessInfo);
begin if Info.hProcess<>0 then TerminateProcess(Info.hProcess,1); Info.IsRunning := False; end;

procedure CleanupProcess(var Info: TProcessInfo);
begin
  if Info.hThread<>0 then CloseHandle(Info.hThread); if Info.hProcess<>0 then CloseHandle(Info.hProcess);
  Info.hThread := 0; Info.hProcess := 0; Info.PID := 0; Info.IsRunning := False;
end;

end.
