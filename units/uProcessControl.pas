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

function TrySetLowIntegrity(hToken: THandle): Boolean;
var Sid: PSID; TIL: PM_TOKEN_MANDATORY_LABEL;
begin
  Result := False; Sid := nil;
  if not AllocateAndInitializeSid(SECURITY_MANDATORY_LABEL_AUTHORITY,1,SECURITY_MANDATORY_LOW_RID,0,0,0,0,0,0,0,Sid) then Exit;
  try TIL.MandatoryLabel.Sid := Sid; TIL.MandatoryLabel.Attributes := SE_GROUP_INTEGRITY;
    Result := PM_SetTokenInformation(hToken, PM_TokenIntegrityLevel, @TIL, SizeOf(TIL)+GetLengthSid(Sid));
  finally FreeSid(Sid); end;
end;

function TryRestricted(const P: string; out PI: TProcessInformation; out E: string): Boolean;
var hC,hN: THandle; SI: TStartupInfo; Cmd: string;
begin
  Result := False; hC := 0; hN := 0;
  if not OpenProcessToken(GetCurrentProcess,TOKEN_ALL_ACCESS,hC) then begin E := SysErrorMessage(GetLastError); Exit; end;
  try
    if not PM_CreateRestrictedToken(hC,DISABLE_MAX_PRIVILEGE,0,nil,0,nil,0,nil,hN) then begin E := SysErrorMessage(GetLastError); Exit; end;
    try TrySetLowIntegrity(hN); FillChar(SI,SizeOf(SI),0); SI.cb := SizeOf(SI);
      Cmd := '"'+P+'"'; FillChar(PI,SizeOf(PI),0);
      Result := PM_CreateProcessAsUser(hN,nil,PChar(Cmd),nil,nil,False,PM_CREATE_SUSPENDED or PM_CREATE_NEW_CONSOLE,nil,nil,SI,PI);
      if not Result then E := SysErrorMessage(GetLastError);
    finally CloseHandle(hN); end;
  finally CloseHandle(hC); end;
end;

function TryNormal(const P: string; out PI: TProcessInformation; out E: string): Boolean;
var SI: TStartupInfo; Cmd: string;
begin
  FillChar(SI,SizeOf(SI),0); SI.cb := SizeOf(SI); FillChar(PI,SizeOf(PI),0); Cmd := '"'+P+'"';
  Result := CreateProcess(nil,PChar(Cmd),nil,nil,False,PM_CREATE_SUSPENDED or PM_CREATE_NEW_CONSOLE,nil,nil,SI,PI);
  if not Result then E := SysErrorMessage(GetLastError);
end;

function LaunchProcess(const APath: string; out Info: TProcessInfo): Boolean;
var PI: TProcessInformation; E: string;
begin
  Info.ExePath := APath; Info.PID := 0; Info.hProcess := 0; Info.hThread := 0;
  Info.IsRunning := False; Info.UsedRestricted := False; Info.ErrorMsg := '';
  Result := TryRestricted(APath,PI,E);
  if Result then Info.UsedRestricted := True
  else begin Info.UsedRestricted := False; Result := TryNormal(APath,PI,E); end;
  if Result then begin Info.PID := PI.dwProcessId; Info.hProcess := PI.hProcess;
    Info.hThread := PI.hThread; Info.IsRunning := True; ResumeThread(PI.hThread);
  end else begin Info.IsRunning := False; Info.ErrorMsg := E; end;
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
