unit uMainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.ShellAPI,
  System.SysUtils, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls,
  Vcl.ExtCtrls, Vcl.Graphics, Vcl.Menus, Vcl.Clipbrd,
  uWinTypes, uProcessControl, uNetworkMonitor, uMemoryScanner, uAdvanced;

type
  TfrmMain = class(TForm)
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    pnlDrop: TPanel; lblDropHint: TLabel;
    pnlToolbar: TPanel; lblExePath: TLabel;
    btnStart,btnStop,btnScan,btnSave,btnClear,btnOpen: TButton;
    lblStatus: TLabel;
    pnlInfo: TPanel; lblProcName,lblPID,lblRestricted: TLabel;
    pgTabs: TPageControl;
    tabMonitor,tabMemory,tabHooks,tabCrypto,tabModules,tabPayloads: TTabSheet;
    pnlNetWrap,pnlNetHead: TPanel; lblNetTitle,lblNetCount: TLabel; edtNetSearch: TEdit; lvNet: TListView;
    pnlUrlWrap,pnlUrlHead: TPanel; lblUrlTitle,lblUrlCount: TLabel; edtUrlSearch: TEdit; lvURLs: TListView;
    pnlMemWrap,pnlMemHead: TPanel; lblMemTitle,lblMemCount: TLabel; edtMemSearch: TEdit; lvStrings: TListView;
    pnlRawHead: TPanel; lblRawTitle,lblRawCount,lblRawStatus: TLabel; edtRawSearch: TEdit; lvRaw: TListView;
    pnlHookHead: TPanel; lblHookTitle,lblHookCount: TLabel; edtHookSearch: TEdit; lvHooks: TListView;
    pnlXorWrap,pnlXorHead: TPanel; lblXorTitle,lblXorCount: TLabel; edtXorSearch: TEdit; lvXor: TListView;
    pnlEntWrap,pnlEntHead: TPanel; lblEntTitle,lblEntCount: TLabel; edtEntSearch: TEdit; lvEntropy: TListView;
    pnlSusWrap,pnlSusHead: TPanel; lblSusTitle,lblSusCount: TLabel; edtSusSearch: TEdit; lvSuspicious: TListView;
    pnlPathWrap,pnlPathHead: TPanel; lblPathTitle,lblPathCount: TLabel; edtPathSearch: TEdit; lvPaths: TListView;
    pnlModWrap,pnlModHead: TPanel; lblModTitle,lblModCount: TLabel; edtModSearch: TEdit; lvModules: TListView;
    pnlPayHead: TPanel; lblPayTitle,lblPayCount: TLabel; edtPaySearch: TEdit; lvPayloads: TListView;
    pnlScanBar: TPanel; lblScanTime: TLabel; pbScan: TProgressBar;
    pmCopy,pmExport: TPopupMenu;
    tmrRefresh,tmrScan: TTimer;
    FProc: TProcessInfo; FExe: string; FMon: Boolean;
    FConns: TNetConnectionArray; FStrs: TExtractedStringArray;
    FConnKeys,FStrKeys: TStringList;
    FRawStrs,FRawFiltered: TRawMemStringArray;
    FHooks: THookInfoArray; FXorStrs: TXorResultArray;
    FEntBlocks: TEntropyBlockArray; FSusMods: TSuspiciousModuleArray;
    FPaths: TFilePathEntryArray; FModules: TIATEntryArray;
    FPayloads: TPayloadInfoArray;
    FHookKeys,FXorKeys,FPathKeys: TStringList;
    FTick,FScanSec: Integer;
    FScanRunning: Boolean;
    procedure Build;
    procedure OnDropClick(S: TObject); procedure OnStartClick(S: TObject);
    procedure OnStopClick(S: TObject); procedure OnSaveClick(S: TObject);
    procedure OnClearClick(S: TObject); procedure OnOpenClick(S: TObject);
    procedure OnScanClick(S: TObject);
    procedure OnTimer(S: TObject); procedure OnScanTimer(S: TObject);
    procedure OnNetSearch(S: TObject); procedure OnUrlSearch(S: TObject);
    procedure OnMemSearch(S: TObject); procedure OnRawSearch(S: TObject);
    procedure OnHookSearch(S: TObject); procedure OnXorSearch(S: TObject);
    procedure OnEntSearch(S: TObject); procedure OnSusSearch(S: TObject);
    procedure OnPathSearch(S: TObject); procedure OnModSearch(S: TObject);
    procedure OnPaySearch(S: TObject);
    procedure OnCopyClick(S: TObject); procedure OnExportClick(S: TObject);
    procedure WMDropFiles(var M: TWMDropFiles); message WM_DROPFILES;
    procedure SelFile(const P: string);
    procedure FetchLight; procedure FetchMedium; procedure FetchHeavy; procedure FetchAll;
    procedure MergeConns(const New: TNetConnectionArray);
    procedure MergeStrs(const New: TExtractedStringArray);
    procedure MergePaths(const New: TFilePathEntryArray);
    procedure FilterNet; procedure FilterUrl; procedure FilterMem;
    procedure FilterRaw; procedure PopulateRaw;
    procedure FilterHooks; procedure FilterXor; procedure FilterEnt; procedure FilterSus;
    procedure FilterPaths; procedure FilterMods; procedure FilterPayloads;
    procedure UpdInfo; procedure SetMon(A: Boolean);
    procedure ShowDrop(V: Boolean); procedure DoClear;
    procedure DoSave(const AFile: string); procedure DoSaveDialog;
    function MakeHead(AP: TWinControl; const T: string; out LT,LC: TLabel; out E: TEdit; AOn: TNotifyEvent): TPanel;
    function MakeEdit(AP: TWinControl; AOn: TNotifyEvent): TEdit;
    function MakeLV(AP: TWinControl): TListView;
    function Wrap(AP: TWinControl; AA: TAlign; AH: Integer): TPanel;
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
var MI: TMenuItem;
begin
  Width:=1160; Height:=860;
  Font.Name:='Segoe UI'; Font.Size:=9;
  FExe:=''; FMon:=False; FTick:=0; FScanSec:=0; FScanRunning:=False;
  SetLength(FConns,0); SetLength(FStrs,0); SetLength(FRawStrs,0); SetLength(FRawFiltered,0);
  SetLength(FHooks,0); SetLength(FXorStrs,0); SetLength(FEntBlocks,0); SetLength(FSusMods,0);
  SetLength(FPaths,0); SetLength(FModules,0); SetLength(FPayloads,0);
  FConnKeys:=TStringList.Create; FConnKeys.Sorted:=True; FConnKeys.Duplicates:=dupIgnore;
  FStrKeys:=TStringList.Create; FStrKeys.Sorted:=True; FStrKeys.Duplicates:=dupIgnore;
  FHookKeys:=TStringList.Create; FHookKeys.Sorted:=True; FHookKeys.Duplicates:=dupIgnore;
  FXorKeys:=TStringList.Create; FXorKeys.Sorted:=True; FXorKeys.Duplicates:=dupIgnore;
  FPathKeys:=TStringList.Create; FPathKeys.Sorted:=True; FPathKeys.Duplicates:=dupIgnore;
  pmCopy:=TPopupMenu.Create(Self);
  MI:=TMenuItem.Create(pmCopy); MI.Caption:='Copy'; MI.OnClick:=OnCopyClick; pmCopy.Items.Add(MI);
  pmExport:=TPopupMenu.Create(Self);
  MI:=TMenuItem.Create(pmExport); MI.Caption:='Copy'; MI.OnClick:=OnCopyClick; pmExport.Items.Add(MI);
  MI:=TMenuItem.Create(pmExport); MI.Caption:='Export Payload...'; MI.OnClick:=OnExportClick; pmExport.Items.Add(MI);
  Build; DragAcceptFiles(Handle,True);
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  DragAcceptFiles(Handle,False);
  if tmrRefresh<>nil then tmrRefresh.Enabled:=False;
  if tmrScan<>nil then tmrScan.Enabled:=False;
  if FProc.IsRunning then KillProcess(FProc);
  CleanupProcess(FProc);
  FConnKeys.Free; FStrKeys.Free; FHookKeys.Free; FXorKeys.Free; FPathKeys.Free;
end;

procedure TfrmMain.WMDropFiles(var M: TWMDropFiles);
var B: array[0..MAX_PATH] of Char; F: string;
begin try if DragQueryFile(M.Drop,0,B,MAX_PATH)>0 then begin F:=B;
    if LowerCase(ExtractFileExt(F))='.exe' then SelFile(F)
    else MessageBox(Handle,'Drop an .exe file.','Invalid',MB_ICONWARNING); end;
  finally DragFinish(M.Drop); end; M.Result:=0; end;

procedure TfrmMain.OnCopyClick(S: TObject);
var LV: TListView; LI: TListItem; Txt: string; I: Integer;
begin LV:=nil; if (ActiveControl is TListView) then LV:=TListView(ActiveControl);
  if LV=nil then Exit; LI:=LV.Selected; if LI=nil then Exit;
  Txt:=LI.Caption; for I:=0 to LI.SubItems.Count-1 do Txt:=Txt+#9+LI.SubItems[I]; Clipboard.AsText:=Txt; end;

procedure TfrmMain.OnExportClick(S: TObject);
var LI: TListItem; Idx: Integer; D: TSaveDialog; FN: string;
begin LI:=lvPayloads.Selected; if LI=nil then Exit;
  Idx:=LI.Index; if (Idx<0) or (Idx>High(FPayloads)) then Exit;
  D:=TSaveDialog.Create(Self);
  try D.Filter:='Binary (*.bin)|*.bin|Executable (*.exe)|*.exe|All (*.*)|*.*';
    D.DefaultExt:='bin'; D.FileName:='payload_'+IntToHex(FPayloads[Idx].Address,8)+'.bin';
    D.Options:=D.Options+[ofOverwritePrompt]; if not D.Execute then Exit; FN:=D.FileName;
  finally D.Free; end; if FN='' then Exit;
  if ExportPayload(FPayloads[Idx],FN) then begin lblStatus.Caption:='Exported!'; lblStatus.Font.Color:=clGreen; end
  else MessageBox(Handle,'Export failed.','Error',MB_ICONERROR); end;

function TfrmMain.MakeHead(AP: TWinControl; const T: string; out LT,LC: TLabel; out E: TEdit; AOn: TNotifyEvent): TPanel;
begin
  Result:=TPanel.Create(Self); Result.Parent:=AP; Result.Align:=alTop;
  Result.Height:=28; Result.BevelOuter:=bvNone;
  LT:=TLabel.Create(Self); LT.Parent:=Result; LT.Left:=8; LT.Top:=5;
  LT.Font.Style:=[fsBold]; LT.Caption:=T;
  LC:=TLabel.Create(Self); LC.Parent:=Result;
  LC.Left:=8+LT.Canvas.TextWidth(T)+8; LC.Top:=6;
  LC.Font.Color:=clGray; LC.Caption:='(0)';
  E:=MakeEdit(Result,AOn);
end;

function TfrmMain.MakeEdit(AP: TWinControl; AOn: TNotifyEvent): TEdit;
begin Result:=TEdit.Create(Self); Result.Parent:=AP;
  Result.Width:=200; Result.Height:=22; Result.Top:=3;
  Result.Left:=AP.Width-212; Result.Anchors:=[akTop,akRight];
  Result.TextHint:='Search...'; Result.OnChange:=AOn; end;

function TfrmMain.MakeLV(AP: TWinControl): TListView;
begin Result:=TListView.Create(Self); Result.Parent:=AP;
  Result.Align:=alClient; Result.ViewStyle:=vsReport;
  Result.RowSelect:=True; Result.GridLines:=True; Result.ReadOnly:=True;
  Result.PopupMenu:=pmCopy; end;

function TfrmMain.Wrap(AP: TWinControl; AA: TAlign; AH: Integer): TPanel;
begin Result:=TPanel.Create(Self); Result.Parent:=AP; Result.Align:=AA;
  Result.Height:=AH; Result.BevelOuter:=bvNone; end;

procedure TfrmMain.Build;
begin
  pnlDrop:=TPanel.Create(Self); pnlDrop.Parent:=Self; pnlDrop.Align:=alClient;
  pnlDrop.BevelOuter:=bvNone; pnlDrop.Cursor:=crHandPoint; pnlDrop.OnClick:=OnDropClick;
  lblDropHint:=TLabel.Create(Self); lblDropHint.Parent:=pnlDrop;
  lblDropHint.AutoSize:=False; lblDropHint.Alignment:=taCenter; lblDropHint.Layout:=tlCenter;
  lblDropHint.WordWrap:=True; lblDropHint.Width:=460; lblDropHint.Height:=120;
  lblDropHint.Left:=(ClientWidth-460) div 2; lblDropHint.Top:=(ClientHeight-120) div 2;
  lblDropHint.Anchors:=[]; lblDropHint.Font.Size:=18; lblDropHint.Font.Color:=clGray;
  lblDropHint.Caption:='MasonRadar'#13#10#13#10'Drag && Drop .exe or click to browse';
  lblDropHint.Cursor:=crHandPoint; lblDropHint.OnClick:=OnDropClick;

  pnlToolbar:=TPanel.Create(Self); pnlToolbar.Parent:=Self; pnlToolbar.Align:=alTop;
  pnlToolbar.Height:=40; pnlToolbar.BevelOuter:=bvNone; pnlToolbar.Visible:=False;
  lblExePath:=TLabel.Create(Self); lblExePath.Parent:=pnlToolbar;
  lblExePath.Left:=8; lblExePath.Top:=12; lblExePath.Width:=380; lblExePath.AutoSize:=False;
  lblExePath.EllipsisPosition:=epPathEllipsis; lblExePath.Font.Size:=10;
  btnStart:=TButton.Create(Self); btnStart.Parent:=pnlToolbar;
  btnStart.SetBounds(470,7,66,26); btnStart.Caption:='Start'; btnStart.Anchors:=[akTop,akRight]; btnStart.OnClick:=OnStartClick;
  btnStop:=TButton.Create(Self); btnStop.Parent:=pnlToolbar;
  btnStop.SetBounds(542,7,66,26); btnStop.Caption:='Stop'; btnStop.Enabled:=False; btnStop.Anchors:=[akTop,akRight]; btnStop.OnClick:=OnStopClick;
  btnScan:=TButton.Create(Self); btnScan.Parent:=pnlToolbar;
  btnScan.SetBounds(614,7,66,26); btnScan.Caption:='Scan'; btnScan.Anchors:=[akTop,akRight]; btnScan.OnClick:=OnScanClick;
  btnSave:=TButton.Create(Self); btnSave.Parent:=pnlToolbar;
  btnSave.SetBounds(686,7,66,26); btnSave.Caption:='Save'; btnSave.Enabled:=False; btnSave.Anchors:=[akTop,akRight]; btnSave.OnClick:=OnSaveClick;
  btnClear:=TButton.Create(Self); btnClear.Parent:=pnlToolbar;
  btnClear.SetBounds(758,7,66,26); btnClear.Caption:='Clear'; btnClear.Enabled:=False; btnClear.Anchors:=[akTop,akRight]; btnClear.OnClick:=OnClearClick;
  btnOpen:=TButton.Create(Self); btnOpen.Parent:=pnlToolbar;
  btnOpen.SetBounds(830,7,66,26); btnOpen.Caption:='Open...'; btnOpen.Anchors:=[akTop,akRight]; btnOpen.OnClick:=OnOpenClick;
  lblStatus:=TLabel.Create(Self); lblStatus.Parent:=pnlToolbar;
  lblStatus.Left:=910; lblStatus.Top:=12; lblStatus.Width:=220;
  lblStatus.Font.Color:=clGray; lblStatus.Anchors:=[akTop,akRight];

  pnlScanBar:=TPanel.Create(Self); pnlScanBar.Parent:=Self; pnlScanBar.Align:=alTop;
  pnlScanBar.Height:=26; pnlScanBar.BevelOuter:=bvNone; pnlScanBar.Visible:=False;
  lblScanTime:=TLabel.Create(Self); lblScanTime.Parent:=pnlScanBar;
  lblScanTime.Left:=8; lblScanTime.Top:=4; lblScanTime.Font.Style:=[fsBold]; lblScanTime.Font.Color:=clNavy;
  pbScan:=TProgressBar.Create(Self); pbScan.Parent:=pnlScanBar;
  pbScan.Left:=200; pbScan.Top:=3; pbScan.Width:=400; pbScan.Height:=18;
  pbScan.Min:=0; pbScan.Max:=60; pbScan.Anchors:=[akTop,akLeft,akRight];

  pnlInfo:=TPanel.Create(Self); pnlInfo.Parent:=Self; pnlInfo.Align:=alTop;
  pnlInfo.Height:=40; pnlInfo.BevelOuter:=bvNone; pnlInfo.Visible:=False;
  lblProcName:=TLabel.Create(Self); lblProcName.Parent:=pnlInfo;
  lblProcName.Left:=8; lblProcName.Top:=2; lblProcName.Font.Size:=10; lblProcName.Font.Style:=[fsBold];
  lblPID:=TLabel.Create(Self); lblPID.Parent:=pnlInfo; lblPID.Left:=8; lblPID.Top:=22; lblPID.Font.Color:=clGray;
  lblRestricted:=TLabel.Create(Self); lblRestricted.Parent:=pnlInfo; lblRestricted.Left:=200; lblRestricted.Top:=22; lblRestricted.Font.Color:=clMaroon;

  pgTabs:=TPageControl.Create(Self); pgTabs.Parent:=Self; pgTabs.Align:=alClient; pgTabs.Visible:=False;
  tabMonitor:=TTabSheet.Create(pgTabs); tabMonitor.PageControl:=pgTabs; tabMonitor.Caption:='Monitor';
  tabMemory:=TTabSheet.Create(pgTabs); tabMemory.PageControl:=pgTabs; tabMemory.Caption:='Memory';
  tabHooks:=TTabSheet.Create(pgTabs); tabHooks.PageControl:=pgTabs; tabHooks.Caption:='Hooks';
  tabCrypto:=TTabSheet.Create(pgTabs); tabCrypto.PageControl:=pgTabs; tabCrypto.Caption:='Crypto / XOR';
  tabModules:=TTabSheet.Create(pgTabs); tabModules.PageControl:=pgTabs; tabModules.Caption:='Modules / Paths';
  tabPayloads:=TTabSheet.Create(pgTabs); tabPayloads.PageControl:=pgTabs; tabPayloads.Caption:='Payloads';

  pnlMemWrap:=Wrap(tabMonitor,alClient,0);
  pnlMemHead:=MakeHead(pnlMemWrap,'Memory Strings (Domains / IPs)',lblMemTitle,lblMemCount,edtMemSearch,OnMemSearch);
  lvStrings:=MakeLV(pnlMemWrap);
  with lvStrings.Columns.Add do begin Caption:='Category'; Width:=80; end;
  with lvStrings.Columns.Add do begin Caption:='Value'; Width:=600; end;
  with lvStrings.Columns.Add do begin Caption:='Address'; Width:=120; end;
  pnlUrlWrap:=Wrap(tabMonitor,alTop,170);
  pnlUrlHead:=MakeHead(pnlUrlWrap,'URLs / Links',lblUrlTitle,lblUrlCount,edtUrlSearch,OnUrlSearch);
  lvURLs:=MakeLV(pnlUrlWrap);
  with lvURLs.Columns.Add do begin Caption:='URL'; Width:=700; end;
  with lvURLs.Columns.Add do begin Caption:='Address'; Width:=120; end;
  pnlNetWrap:=Wrap(tabMonitor,alTop,200);
  pnlNetHead:=MakeHead(pnlNetWrap,'Network Connections',lblNetTitle,lblNetCount,edtNetSearch,OnNetSearch);
  lvNet:=MakeLV(pnlNetWrap);
  with lvNet.Columns.Add do begin Caption:='Proto'; Width:=50; end;
  with lvNet.Columns.Add do begin Caption:='Detection'; Width:=90; end;
  with lvNet.Columns.Add do begin Caption:='Local IP'; Width:=120; end;
  with lvNet.Columns.Add do begin Caption:='LPort'; Width:=55; end;
  with lvNet.Columns.Add do begin Caption:='Remote IP'; Width:=120; end;
  with lvNet.Columns.Add do begin Caption:='RPort'; Width:=55; end;
  with lvNet.Columns.Add do begin Caption:='State'; Width:=95; end;

  pnlRawHead:=TPanel.Create(Self); pnlRawHead.Parent:=tabMemory; pnlRawHead.Align:=alTop;
  pnlRawHead.Height:=32; pnlRawHead.BevelOuter:=bvNone;
  lblRawTitle:=TLabel.Create(Self); lblRawTitle.Parent:=pnlRawHead; lblRawTitle.Left:=8; lblRawTitle.Top:=7;
  lblRawTitle.Font.Style:=[fsBold]; lblRawTitle.Caption:='Full Memory Strings';
  lblRawCount:=TLabel.Create(Self); lblRawCount.Parent:=pnlRawHead; lblRawCount.Left:=160; lblRawCount.Top:=8;
  lblRawCount.Font.Color:=clGray; lblRawCount.Caption:='(0)';
  lblRawStatus:=TLabel.Create(Self); lblRawStatus.Parent:=pnlRawHead; lblRawStatus.Left:=240; lblRawStatus.Top:=8;
  lblRawStatus.Font.Color:=clGray;
  edtRawSearch:=MakeEdit(pnlRawHead,OnRawSearch); edtRawSearch.Top:=5;
  lvRaw:=MakeLV(tabMemory);
  with lvRaw.Columns.Add do begin Caption:='#'; Width:=50; end;
  with lvRaw.Columns.Add do begin Caption:='Address'; Width:=95; end;
  with lvRaw.Columns.Add do begin Caption:='Len'; Width:=45; end;
  with lvRaw.Columns.Add do begin Caption:='Enc'; Width:=50; end;
  with lvRaw.Columns.Add do begin Caption:='Prot'; Width:=40; end;
  with lvRaw.Columns.Add do begin Caption:='Value'; Width:=700; end;

  pnlHookHead:=MakeHead(tabHooks,'API Hook Detection',lblHookTitle,lblHookCount,edtHookSearch,OnHookSearch);
  lvHooks:=MakeLV(tabHooks);
  with lvHooks.Columns.Add do begin Caption:='DLL'; Width:=120; end;
  with lvHooks.Columns.Add do begin Caption:='API'; Width:=200; end;
  with lvHooks.Columns.Add do begin Caption:='Address'; Width:=110; end;
  with lvHooks.Columns.Add do begin Caption:='Status'; Width:=70; end;
  with lvHooks.Columns.Add do begin Caption:='Type'; Width:=120; end;
  with lvHooks.Columns.Add do begin Caption:='Bytes'; Width:=280; end;

  pnlEntWrap:=Wrap(tabCrypto,alClient,0);
  pnlEntHead:=MakeHead(pnlEntWrap,'High Entropy (Encrypted / Packed)',lblEntTitle,lblEntCount,edtEntSearch,OnEntSearch);
  lvEntropy:=MakeLV(pnlEntWrap);
  with lvEntropy.Columns.Add do begin Caption:='Address'; Width:=120; end;
  with lvEntropy.Columns.Add do begin Caption:='Size'; Width:=90; end;
  with lvEntropy.Columns.Add do begin Caption:='Entropy'; Width:=90; end;
  with lvEntropy.Columns.Add do begin Caption:='Protection'; Width:=90; end;
  pnlXorWrap:=Wrap(tabCrypto,alTop,280);
  pnlXorHead:=MakeHead(pnlXorWrap,'XOR Encoded Strings',lblXorTitle,lblXorCount,edtXorSearch,OnXorSearch);
  lvXor:=MakeLV(pnlXorWrap);
  with lvXor.Columns.Add do begin Caption:='Key'; Width:=60; end;
  with lvXor.Columns.Add do begin Caption:='Address'; Width:=110; end;
  with lvXor.Columns.Add do begin Caption:='Decoded Value'; Width:=700; end;

  pnlSusWrap:=Wrap(tabModules,alBottom,240);
  pnlSusHead:=MakeHead(pnlSusWrap,'Suspicious Modules',lblSusTitle,lblSusCount,edtSusSearch,OnSusSearch);
  lvSuspicious:=MakeLV(pnlSusWrap);
  with lvSuspicious.Columns.Add do begin Caption:='Module'; Width:=150; end;
  with lvSuspicious.Columns.Add do begin Caption:='Path'; Width:=380; end;
  with lvSuspicious.Columns.Add do begin Caption:='Reason'; Width:=240; end;
  pnlPathWrap:=Wrap(tabModules,alClient,0);
  pnlPathHead:=MakeHead(pnlPathWrap,'File Paths / Registry Keys',lblPathTitle,lblPathCount,edtPathSearch,OnPathSearch);
  lvPaths:=MakeLV(pnlPathWrap);
  with lvPaths.Columns.Add do begin Caption:='Type'; Width:=85; end;
  with lvPaths.Columns.Add do begin Caption:='Path'; Width:=590; end;
  with lvPaths.Columns.Add do begin Caption:='Address'; Width:=110; end;
  pnlModWrap:=Wrap(tabModules,alTop,240);
  pnlModHead:=MakeHead(pnlModWrap,'Loaded Modules (DLLs)',lblModTitle,lblModCount,edtModSearch,OnModSearch);
  lvModules:=MakeLV(pnlModWrap);
  with lvModules.Columns.Add do begin Caption:='Module'; Width:=190; end;
  with lvModules.Columns.Add do begin Caption:='Path'; Width:=600; end;

  pnlPayHead:=MakeHead(tabPayloads,'Embedded Payloads (PE in Memory)',lblPayTitle,lblPayCount,edtPaySearch,OnPaySearch);
  lvPayloads:=MakeLV(tabPayloads); lvPayloads.PopupMenu:=pmExport; lvPayloads.Font.Color:=clRed;
  with lvPayloads.Columns.Add do begin Caption:='Address'; Width:=130; end;
  with lvPayloads.Columns.Add do begin Caption:='Size'; Width:=110; end;
  with lvPayloads.Columns.Add do begin Caption:='PE Type'; Width:=140; end;
  with lvPayloads.Columns.Add do begin Caption:='Protection'; Width:=110; end;

  tmrRefresh:=TTimer.Create(Self); tmrRefresh.Interval:=3000; tmrRefresh.Enabled:=False; tmrRefresh.OnTimer:=OnTimer;
  tmrScan:=TTimer.Create(Self); tmrScan.Interval:=1000; tmrScan.Enabled:=False; tmrScan.OnTimer:=OnScanTimer;
  ShowDrop(True);
end;

procedure TfrmMain.OnDropClick(S: TObject);
var D: TOpenDialog;
begin D:=TOpenDialog.Create(Self); try D.Filter:='Executables (*.exe)|*.exe|All (*.*)|*.*';
  D.Title:='Select executable'; if D.Execute then SelFile(D.FileName); finally D.Free; end; end;
procedure TfrmMain.OnOpenClick(S: TObject); begin OnDropClick(S); end;

procedure TfrmMain.SelFile(const P: string);
begin if FMon then begin SetMon(False); KillProcess(FProc); CleanupProcess(FProc); end;
  if FScanRunning then begin tmrScan.Enabled:=False; FScanRunning:=False; pnlScanBar.Visible:=False; end;
  FExe:=P; lblExePath.Caption:=FExe; btnStart.Enabled:=True; btnStop.Enabled:=False;
  btnSave.Enabled:=False; btnClear.Enabled:=False; btnScan.Enabled:=True;
  lblStatus.Caption:='Ready'; lblStatus.Font.Color:=clGray; DoClear; ShowDrop(False); end;

procedure TfrmMain.OnStartClick(S: TObject);
begin if FExe='' then Exit;
  if FProc.hProcess<>0 then begin KillProcess(FProc); CleanupProcess(FProc); end; DoClear;
  if not LaunchProcess(FExe,FProc) then begin MessageBox(Handle,PChar('Failed:'#13#10+FProc.ErrorMsg),'Error',MB_ICONERROR); Exit; end;
  UpdInfo; SetMon(True); btnSave.Enabled:=True; btnClear.Enabled:=True; btnScan.Enabled:=True; end;

procedure TfrmMain.OnStopClick(S: TObject);
begin SetMon(False); KillProcess(FProc); CleanupProcess(FProc);
  lblStatus.Caption:='Stopped'; lblStatus.Font.Color:=clRed; btnStop.Enabled:=False; btnStart.Enabled:=(FExe<>''); end;
procedure TfrmMain.OnClearClick(S: TObject); begin DoClear; end;
procedure TfrmMain.OnSaveClick(S: TObject); begin DoSaveDialog; end;

procedure TfrmMain.OnScanClick(S: TObject);
begin if FScanRunning or (FExe='') then Exit;
  if FProc.PID=0 then begin
    if FProc.hProcess<>0 then begin KillProcess(FProc); CleanupProcess(FProc); end; DoClear;
    if not LaunchProcess(FExe,FProc) then begin MessageBox(Handle,PChar('Failed:'#13#10+FProc.ErrorMsg),'Error',MB_ICONERROR); Exit; end;
    UpdInfo; end;
  FScanRunning:=True; FScanSec:=0;
  pnlScanBar.Visible:=True; pbScan.Position:=0;
  lblScanTime.Caption:='Scanning: 0 / 60 sec';
  lblStatus.Caption:='Scanning...'; lblStatus.Font.Color:=clNavy;
  btnScan.Enabled:=False; btnStart.Enabled:=False; btnStop.Enabled:=False;
  tmrRefresh.Enabled:=False; tmrScan.Enabled:=True; end;

procedure TfrmMain.OnScanTimer(S: TObject);
var RF: string;
begin Inc(FScanSec); pbScan.Position:=FScanSec;
  lblScanTime.Caption:=Format('Scanning: %d / 60 sec',[FScanSec]);
  Application.ProcessMessages;
  if IsProcessAlive(FProc) then FetchAll;
  if FScanSec>=60 then begin
    tmrScan.Enabled:=False; FScanRunning:=False; pnlScanBar.Visible:=False;
    btnScan.Enabled:=True; btnStart.Enabled:=True; btnSave.Enabled:=True; btnClear.Enabled:=True;
    KillProcess(FProc); CleanupProcess(FProc); btnStop.Enabled:=False;
    RF:=ExtractFilePath(FExe)+ChangeFileExt(ExtractFileName(FExe),'')+'_MasonRadar_'+FormatDateTime('yyyymmdd_hhnnss',Now)+'.txt';
    DoSave(RF);
    lblStatus.Caption:='Scan complete!'; lblStatus.Font.Color:=clGreen;
    ShellExecute(Handle,'open',PChar(RF),nil,nil,SW_SHOWNORMAL);
  end; end;

procedure TfrmMain.OnTimer(S: TObject);
begin if not IsProcessAlive(FProc) then begin SetMon(False); lblStatus.Caption:='Exited';
    lblStatus.Font.Color:=clRed; btnStop.Enabled:=False; btnStart.Enabled:=(FExe<>'');
    CleanupProcess(FProc); Exit; end;
  Inc(FTick);
  case (FTick mod 3) of 0: FetchLight; 1: FetchMedium; 2: FetchHeavy; end; end;

procedure TfrmMain.FetchAll; begin FetchLight; FetchMedium; FetchHeavy; end;

procedure TfrmMain.FetchLight;
begin MergeConns(GetConnectionsForPID(FProc.PID)); MergeStrs(ScanProcessMemory(FProc.PID));
  FilterNet; FilterUrl; FilterMem; end;

procedure TfrmMain.FetchMedium;
var New: TRawMemStringArray; I,X: Integer; Seen: TStringList;
begin if FProc.PID=0 then Exit;
  New:=ScanProcessMemoryFull(FProc.PID,4); Seen:=TStringList.Create;
  try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore;
    for I:=0 to High(FRawStrs) do Seen.Add(FRawStrs[I].Value);
    for I:=0 to High(New) do begin if Seen.IndexOf(New[I].Value)>=0 then Continue; Seen.Add(New[I].Value);
      X:=Length(FRawStrs); SetLength(FRawStrs,X+1); FRawStrs[X]:=New[I]; end;
  finally Seen.Free; end; FilterRaw;
  MergePaths(ScanFilePaths(FProc.PID)); FilterPaths; end;

procedure TfrmMain.FetchHeavy;
var NewH: THookInfoArray; NewX: TXorResultArray; I,X: Integer;
begin if FProc.PID=0 then Exit;
  NewH:=DetectHooks(FProc.PID);
  for I:=0 to High(NewH) do begin
    if FHookKeys.IndexOf(NewH[I].APIName)>=0 then begin
      for X:=0 to High(FHooks) do if FHooks[X].APIName=NewH[I].APIName then begin FHooks[X]:=NewH[I]; Break; end; Continue; end;
    FHookKeys.Add(NewH[I].APIName); X:=Length(FHooks); SetLength(FHooks,X+1); FHooks[X]:=NewH[I]; end;
  FilterHooks;
  NewX:=ScanXorStrings(FProc.PID);
  for I:=0 to High(NewX) do begin if FXorKeys.IndexOf(NewX[I].Decoded)>=0 then Continue;
    FXorKeys.Add(NewX[I].Decoded); X:=Length(FXorStrs); SetLength(FXorStrs,X+1); FXorStrs[X]:=NewX[I]; end;
  FilterXor;
  FEntBlocks:=ScanEntropy(FProc.PID); FilterEnt;
  FSusMods:=DetectSuspiciousModules(FProc.PID); FilterSus;
  FModules:=ReadIATImports(FProc.PID); FilterMods;
  FPayloads:=ScanPayloads(FProc.PID); FilterPayloads; end;

procedure TfrmMain.MergeConns(const New: TNetConnectionArray);
var I,X: Integer; Key: string;
begin for I:=0 to High(New) do begin Key:=New[I].Protocol+'|'+New[I].LocalAddr+':'+IntToStr(New[I].LocalPort)+'|'+New[I].RemoteAddr+':'+IntToStr(New[I].RemotePort);
  if FConnKeys.IndexOf(Key)>=0 then begin for X:=0 to High(FConns) do
    if (FConns[X].LocalAddr=New[I].LocalAddr) and (FConns[X].LocalPort=New[I].LocalPort) and
       (FConns[X].RemoteAddr=New[I].RemoteAddr) and (FConns[X].RemotePort=New[I].RemotePort) then begin FConns[X].State:=New[I].State; Break; end;
    Continue; end; FConnKeys.Add(Key); X:=Length(FConns); SetLength(FConns,X+1); FConns[X]:=New[I]; end; end;

procedure TfrmMain.MergeStrs(const New: TExtractedStringArray);
var I,X: Integer;
begin for I:=0 to High(New) do begin if FStrKeys.IndexOf(New[I].Value)>=0 then Continue;
  FStrKeys.Add(New[I].Value); X:=Length(FStrs); SetLength(FStrs,X+1); FStrs[X]:=New[I]; end; end;

procedure TfrmMain.MergePaths(const New: TFilePathEntryArray);
var I,X: Integer;
begin for I:=0 to High(New) do begin if FPathKeys.IndexOf(New[I].Value)>=0 then Continue;
  FPathKeys.Add(New[I].Value); X:=Length(FPaths); SetLength(FPaths,X+1); FPaths[X]:=New[I]; end; end;

procedure TfrmMain.OnNetSearch(S: TObject); begin FilterNet; end;
procedure TfrmMain.OnUrlSearch(S: TObject); begin FilterUrl; end;
procedure TfrmMain.OnMemSearch(S: TObject); begin FilterMem; end;
procedure TfrmMain.OnRawSearch(S: TObject); begin FilterRaw; end;
procedure TfrmMain.OnHookSearch(S: TObject); begin FilterHooks; end;
procedure TfrmMain.OnXorSearch(S: TObject); begin FilterXor; end;
procedure TfrmMain.OnEntSearch(S: TObject); begin FilterEnt; end;
procedure TfrmMain.OnSusSearch(S: TObject); begin FilterSus; end;
procedure TfrmMain.OnPathSearch(S: TObject); begin FilterPaths; end;
procedure TfrmMain.OnModSearch(S: TObject); begin FilterMods; end;
procedure TfrmMain.OnPaySearch(S: TObject); begin FilterPayloads; end;

procedure TfrmMain.FilterNet;
var I,N: Integer; LI: TListItem; F,Row: string;
begin F:=LowerCase(Trim(edtNetSearch.Text)); N:=0; lvNet.Items.BeginUpdate; try lvNet.Items.Clear;
  for I:=0 to High(FConns) do begin Row:=LowerCase(FConns[I].Protocol+' '+FConns[I].Detection+' '+FConns[I].LocalAddr+' '+IntToStr(FConns[I].LocalPort)+' '+FConns[I].RemoteAddr+' '+IntToStr(FConns[I].RemotePort)+' '+FConns[I].State);
    if (F<>'') and (Pos(F,Row)=0) then Continue; LI:=lvNet.Items.Add; LI.Caption:=FConns[I].Protocol;
    LI.SubItems.Add(FConns[I].Detection); LI.SubItems.Add(FConns[I].LocalAddr); LI.SubItems.Add(IntToStr(FConns[I].LocalPort));
    LI.SubItems.Add(FConns[I].RemoteAddr); if FConns[I].RemotePort>0 then LI.SubItems.Add(IntToStr(FConns[I].RemotePort)) else LI.SubItems.Add('*');
    LI.SubItems.Add(FConns[I].State); Inc(N); end; finally lvNet.Items.EndUpdate; end; lblNetCount.Caption:=Format('(%d/%d)',[N,Length(FConns)]); end;

procedure TfrmMain.FilterUrl;
var I,N: Integer; LI: TListItem; F: string; Seen: TStringList;
begin F:=LowerCase(Trim(edtUrlSearch.Text)); N:=0; Seen:=TStringList.Create;
  try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore; lvURLs.Items.BeginUpdate; try lvURLs.Items.Clear;
    for I:=0 to High(FStrs) do begin if FStrs[I].Category<>scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
      if (F<>'') and (Pos(F,LowerCase(FStrs[I].Value))=0) then Continue;
      LI:=lvURLs.Items.Add; LI.Caption:=FStrs[I].Value; LI.SubItems.Add(Format('0x%x',[FStrs[I].Address])); Inc(N);
    end; finally lvURLs.Items.EndUpdate; end; finally Seen.Free; end; lblUrlCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterMem;
var I,N: Integer; LI: TListItem; F,CS: string; Seen: TStringList;
begin F:=LowerCase(Trim(edtMemSearch.Text)); N:=0; Seen:=TStringList.Create;
  try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore; lvStrings.Items.BeginUpdate; try lvStrings.Items.Clear;
    for I:=0 to High(FStrs) do begin if FStrs[I].Category=scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value); CS:=CategoryLabel(FStrs[I].Category);
      if (F<>'') and (Pos(F,LowerCase(CS+' '+FStrs[I].Value))=0) then Continue;
      LI:=lvStrings.Items.Add; LI.Caption:=CS; LI.SubItems.Add(FStrs[I].Value); LI.SubItems.Add(Format('0x%x',[FStrs[I].Address])); Inc(N);
    end; finally lvStrings.Items.EndUpdate; end; finally Seen.Free; end; lblMemCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterRaw;
var I,N: Integer; F: string;
begin F:=LowerCase(Trim(edtRawSearch.Text)); N:=0; SetLength(FRawFiltered,0);
  for I:=0 to High(FRawStrs) do begin if (F<>'') and (Pos(F,LowerCase(FRawStrs[I].Value))=0) then Continue;
    SetLength(FRawFiltered,N+1); FRawFiltered[N]:=FRawStrs[I]; Inc(N); end;
  lblRawCount.Caption:=Format('(%d/%d)',[N,Length(FRawStrs)]); lblRawStatus.Caption:=Format('Total: %d',[Length(FRawStrs)]); PopulateRaw; end;

procedure TfrmMain.PopulateRaw;
var I,Max: Integer; LI: TListItem;
begin Max:=30000; lvRaw.Items.BeginUpdate; try lvRaw.Items.Clear;
  for I:=0 to High(FRawFiltered) do begin if I>=Max then Break;
    LI:=lvRaw.Items.Add; LI.Caption:=IntToStr(I+1); LI.SubItems.Add(Format('0x%x',[FRawFiltered[I].Address]));
    LI.SubItems.Add(IntToStr(FRawFiltered[I].Len)); LI.SubItems.Add(FRawFiltered[I].Encoding);
    LI.SubItems.Add(FRawFiltered[I].Protect); LI.SubItems.Add(FRawFiltered[I].Value);
  end; finally lvRaw.Items.EndUpdate; end; end;

procedure TfrmMain.FilterHooks;
var I,N: Integer; LI: TListItem; F,Row: string;
begin F:=LowerCase(Trim(edtHookSearch.Text)); N:=0; lvHooks.Items.BeginUpdate;
  try lvHooks.Items.Clear; for I:=0 to High(FHooks) do begin Row:=LowerCase(FHooks[I].DLLName+' '+FHooks[I].APIName+' '+FHooks[I].HookType);
    if (F<>'') and (Pos(F,Row)=0) then Continue; LI:=lvHooks.Items.Add; LI.Caption:=FHooks[I].DLLName;
    LI.SubItems.Add(FHooks[I].APIName); LI.SubItems.Add(Format('0x%x',[FHooks[I].Address]));
    if FHooks[I].Hooked then LI.SubItems.Add('HOOKED') else LI.SubItems.Add('Clean');
    LI.SubItems.Add(FHooks[I].HookType); LI.SubItems.Add(FHooks[I].Bytes); Inc(N);
  end; finally lvHooks.Items.EndUpdate; end; lblHookCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterXor;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtXorSearch.Text)); N:=0; lvXor.Items.BeginUpdate;
  try lvXor.Items.Clear; for I:=0 to High(FXorStrs) do begin
    if (F<>'') and (Pos(F,LowerCase(FXorStrs[I].Decoded))=0) then Continue; LI:=lvXor.Items.Add;
    LI.Caption:=FXorStrs[I].KeyHex; LI.SubItems.Add(Format('0x%x',[FXorStrs[I].Address]));
    LI.SubItems.Add(FXorStrs[I].Decoded); Inc(N);
  end; finally lvXor.Items.EndUpdate; end; lblXorCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterEnt;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtEntSearch.Text)); N:=0; lvEntropy.Items.BeginUpdate;
  try lvEntropy.Items.Clear; for I:=0 to High(FEntBlocks) do begin
    if (F<>'') and (Pos(F,LowerCase(FEntBlocks[I].Protect))=0) then Continue; LI:=lvEntropy.Items.Add;
    LI.Caption:=Format('0x%x',[FEntBlocks[I].Address]); LI.SubItems.Add(IntToStr(FEntBlocks[I].Size));
    LI.SubItems.Add(Format('%.3f',[FEntBlocks[I].Entropy])); LI.SubItems.Add(FEntBlocks[I].Protect); Inc(N);
  end; finally lvEntropy.Items.EndUpdate; end; lblEntCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterSus;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtSusSearch.Text)); N:=0; lvSuspicious.Items.BeginUpdate;
  try lvSuspicious.Items.Clear; for I:=0 to High(FSusMods) do begin
    if (F<>'') and (Pos(F,LowerCase(FSusMods[I].Name+' '+FSusMods[I].Reason))=0) then Continue;
    LI:=lvSuspicious.Items.Add; LI.Caption:=FSusMods[I].Name; LI.SubItems.Add(FSusMods[I].Path);
    LI.SubItems.Add(FSusMods[I].Reason); Inc(N);
  end; finally lvSuspicious.Items.EndUpdate; end; lblSusCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterPaths;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtPathSearch.Text)); N:=0; lvPaths.Items.BeginUpdate;
  try lvPaths.Items.Clear; for I:=0 to High(FPaths) do begin
    if (F<>'') and (Pos(F,LowerCase(FPaths[I].Value))=0) then Continue;
    LI:=lvPaths.Items.Add; LI.Caption:=FPaths[I].PathType; LI.SubItems.Add(FPaths[I].Value);
    LI.SubItems.Add(Format('0x%x',[FPaths[I].Address])); Inc(N);
  end; finally lvPaths.Items.EndUpdate; end; lblPathCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterMods;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtModSearch.Text)); N:=0; lvModules.Items.BeginUpdate;
  try lvModules.Items.Clear; for I:=0 to High(FModules) do begin
    if (F<>'') and (Pos(F,LowerCase(FModules[I].DLLName+' '+FModules[I].FuncName))=0) then Continue;
    LI:=lvModules.Items.Add; LI.Caption:=FModules[I].DLLName; LI.SubItems.Add(FModules[I].FuncName); Inc(N);
  end; finally lvModules.Items.EndUpdate; end; lblModCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.FilterPayloads;
var I,N: Integer; LI: TListItem; F: string;
begin F:=LowerCase(Trim(edtPaySearch.Text)); N:=0; lvPayloads.Items.BeginUpdate;
  try lvPayloads.Items.Clear; for I:=0 to High(FPayloads) do begin
    if (F<>'') and (Pos(F,LowerCase(FPayloads[I].PEType))=0) then Continue;
    LI:=lvPayloads.Items.Add; LI.Caption:=Format('0x%x',[FPayloads[I].Address]);
    LI.SubItems.Add(IntToStr(FPayloads[I].Size)); LI.SubItems.Add(FPayloads[I].PEType);
    LI.SubItems.Add(FPayloads[I].Protect); Inc(N);
  end; finally lvPayloads.Items.EndUpdate; end; lblPayCount.Caption:=Format('(%d)',[N]); end;

procedure TfrmMain.DoSaveDialog;
var D: TSaveDialog; FN: string;
begin FN:='MasonRadar_'+FormatDateTime('yyyymmdd_hhnnss',Now)+'.txt';
  D:=TSaveDialog.Create(Self); try D.Filter:='Text files (*.txt)|*.txt|All files (*.*)|*.*';
    D.DefaultExt:='txt'; D.FileName:=FN; D.Options:=D.Options+[ofOverwritePrompt];
    if not D.Execute then Exit; FN:=D.FileName; finally D.Free; end;
  if FN='' then Exit; DoSave(FN); end;

procedure TfrmMain.DoSave(const AFile: string);
var SL,Seen: TStringList; I: Integer;
begin SL:=TStringList.Create; Seen:=TStringList.Create;
  try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore;
    SL.Add('=== MasonRadar Report ==='); SL.Add('Date: '+DateTimeToStr(Now));
    SL.Add('Process: '+ExtractFileName(FExe)); SL.Add('Path: '+FExe); SL.Add('PID: '+IntToStr(FProc.PID)); SL.Add('');
    SL.Add('--- Network ('+IntToStr(Length(FConns))+') ---'); SL.Add('');
    for I:=0 to High(FConns) do SL.Add(Format('  %-5s %-11s %-16s:%-5d -> %-16s:%-5d %s',
      [FConns[I].Protocol,FConns[I].Detection,FConns[I].LocalAddr,FConns[I].LocalPort,FConns[I].RemoteAddr,FConns[I].RemotePort,FConns[I].State]));
    SL.Add(''); SL.Add('--- URLs ---'); SL.Add(''); Seen.Clear;
    for I:=0 to High(FStrs) do begin if FStrs[I].Category<>scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value); SL.Add('  '+FStrs[I].Value); end;
    SL.Add(''); SL.Add('--- Domains / IPs ---'); SL.Add(''); Seen.Clear;
    for I:=0 to High(FStrs) do begin if FStrs[I].Category=scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
      SL.Add(Format('  [%-8s] %s',[CategoryLabel(FStrs[I].Category),FStrs[I].Value])); end;
    SL.Add(''); SL.Add('--- File Paths ---'); SL.Add('');
    for I:=0 to High(FPaths) do SL.Add(Format('  [%-10s] %s',[FPaths[I].PathType,FPaths[I].Value]));
    SL.Add(''); SL.Add('--- API Hooks ---'); SL.Add('');
    for I:=0 to High(FHooks) do SL.Add(Format('  [%-7s] %s!%s %s',[FHooks[I].HookType,FHooks[I].DLLName,FHooks[I].APIName,FHooks[I].Bytes]));
    SL.Add(''); SL.Add('--- XOR Strings ---'); SL.Add('');
    for I:=0 to High(FXorStrs) do SL.Add(Format('  Key=%s Addr=0x%x -> %s',[FXorStrs[I].KeyHex,FXorStrs[I].Address,FXorStrs[I].Decoded]));
    SL.Add(''); SL.Add('--- Entropy ---'); SL.Add('');
    for I:=0 to High(FEntBlocks) do SL.Add(Format('  0x%x Size=%d E=%.3f %s',[FEntBlocks[I].Address,FEntBlocks[I].Size,FEntBlocks[I].Entropy,FEntBlocks[I].Protect]));
    SL.Add(''); SL.Add('--- Payloads ---'); SL.Add('');
    for I:=0 to High(FPayloads) do SL.Add(Format('  0x%x Size=%d %s %s',[FPayloads[I].Address,FPayloads[I].Size,FPayloads[I].PEType,FPayloads[I].Protect]));
    SL.Add(''); SL.Add('--- Modules ---'); SL.Add('');
    for I:=0 to High(FModules) do SL.Add(Format('  %s -> %s',[FModules[I].DLLName,FModules[I].FuncName]));
    SL.Add(''); SL.Add('--- Suspicious ---'); SL.Add('');
    for I:=0 to High(FSusMods) do SL.Add(Format('  %s (%s) %s',[FSusMods[I].Name,FSusMods[I].Path,FSusMods[I].Reason]));
    SL.Add(''); SL.Add('=== End ===');
    try SL.SaveToFile(AFile); lblStatus.Caption:='Saved!'; lblStatus.Font.Color:=clGreen;
    except on E: Exception do MessageBox(Handle,PChar('Save failed: '+E.Message),'Error',MB_ICONERROR); end;
  finally Seen.Free; SL.Free; end; end;

procedure TfrmMain.UpdInfo;
begin lblProcName.Caption:='Process: '+ExtractFileName(FProc.ExePath);
  lblPID.Caption:='PID: '+IntToStr(FProc.PID);
  if FProc.UsedRestricted then lblRestricted.Caption:='[Restricted / Low-Integrity Token]'
  else lblRestricted.Caption:='[Standard Token]'; end;

procedure TfrmMain.SetMon(A: Boolean);
begin FMon:=A; tmrRefresh.Enabled:=A; btnStop.Enabled:=A; btnStart.Enabled:=not A; FTick:=0;
  if A then begin lblStatus.Caption:='Monitoring...'; lblStatus.Font.Color:=clGreen; FetchLight; end; end;

procedure TfrmMain.ShowDrop(V: Boolean);
begin pnlDrop.Visible:=V; pnlToolbar.Visible:=not V; pnlInfo.Visible:=not V; pgTabs.Visible:=not V;
  pnlScanBar.Visible:=False;
  if V then begin lblDropHint.Left:=(pnlDrop.ClientWidth-lblDropHint.Width) div 2;
    lblDropHint.Top:=(pnlDrop.ClientHeight-lblDropHint.Height) div 2; end; end;

procedure TfrmMain.DoClear;
begin
  SetLength(FConns,0); SetLength(FStrs,0); SetLength(FRawStrs,0); SetLength(FRawFiltered,0);
  SetLength(FHooks,0); SetLength(FXorStrs,0); SetLength(FEntBlocks,0); SetLength(FSusMods,0);
  SetLength(FPaths,0); SetLength(FModules,0); SetLength(FPayloads,0);
  FConnKeys.Clear; FStrKeys.Clear; FHookKeys.Clear; FXorKeys.Clear; FPathKeys.Clear; FTick:=0;
  if lvNet<>nil then lvNet.Items.Clear; if lvURLs<>nil then lvURLs.Items.Clear;
  if lvStrings<>nil then lvStrings.Items.Clear; if lvRaw<>nil then lvRaw.Items.Clear;
  if lvHooks<>nil then lvHooks.Items.Clear; if lvXor<>nil then lvXor.Items.Clear;
  if lvEntropy<>nil then lvEntropy.Items.Clear; if lvSuspicious<>nil then lvSuspicious.Items.Clear;
  if lvPaths<>nil then lvPaths.Items.Clear; if lvModules<>nil then lvModules.Items.Clear;
  if lvPayloads<>nil then lvPayloads.Items.Clear;
  if lblNetCount<>nil then lblNetCount.Caption:='(0)'; if lblUrlCount<>nil then lblUrlCount.Caption:='(0)';
  if lblMemCount<>nil then lblMemCount.Caption:='(0)'; if lblRawCount<>nil then lblRawCount.Caption:='(0)';
  if lblHookCount<>nil then lblHookCount.Caption:='(0)'; if lblXorCount<>nil then lblXorCount.Caption:='(0)';
  if lblEntCount<>nil then lblEntCount.Caption:='(0)'; if lblSusCount<>nil then lblSusCount.Caption:='(0)';
  if lblPathCount<>nil then lblPathCount.Caption:='(0)'; if lblModCount<>nil then lblModCount.Caption:='(0)';
  if lblPayCount<>nil then lblPayCount.Caption:='(0)'; if lblRawStatus<>nil then lblRawStatus.Caption:='';
  if edtNetSearch<>nil then edtNetSearch.Text:=''; if edtUrlSearch<>nil then edtUrlSearch.Text:='';
  if edtMemSearch<>nil then edtMemSearch.Text:=''; if edtRawSearch<>nil then edtRawSearch.Text:='';
  if edtHookSearch<>nil then edtHookSearch.Text:=''; if edtXorSearch<>nil then edtXorSearch.Text:='';
  if edtEntSearch<>nil then edtEntSearch.Text:=''; if edtSusSearch<>nil then edtSusSearch.Text:='';
  if edtPathSearch<>nil then edtPathSearch.Text:=''; if edtModSearch<>nil then edtModSearch.Text:='';
  if edtPaySearch<>nil then edtPaySearch.Text:='';
  lblProcName.Caption:=''; lblPID.Caption:=''; lblRestricted.Caption:=''; end;

end.
