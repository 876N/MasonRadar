program MasonRadar;

uses
  Vcl.Forms,
  uWinTypes        in 'units\uWinTypes.pas',
  uProcessControl  in 'units\uProcessControl.pas',
  uNetworkMonitor  in 'units\uNetworkMonitor.pas',
  uMemoryScanner   in 'units\uMemoryScanner.pas',
  uMainForm        in 'forms\uMainForm.pas' {frmMain};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'MasonRadar';
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
