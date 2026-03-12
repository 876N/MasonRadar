unit uMainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.ShellAPI,
  System.SysUtils, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls,
  Vcl.ExtCtrls, Vcl.Graphics, Vcl.Menus, Vcl.Clipbrd,
  uWinTypes, uProcessControl, uNetworkMonitor, uMemoryScanner;

type
  TfrmMain = class(TForm)
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    pnlTitle: TPanel; lblTitle: TLabel;
    btnMin, btnMax, btnClose: TLabel;
    FDrag: Boolean; FDragPt: TPoint; FIsMax: Boolean; FRestore: TRect;
    pnlGripR, pnlGripB, pnlGripRB: TPanel;
    pnlDrop: TPanel; lblDropHint: TLabel;
    pnlToolbar: TPanel; lblExePath: TLabel;
    btnLaunch, btnStop, btnSave, btnClear, btnNewFile: TButton;
    lblStatus: TLabel;
    pnlInfo: TPanel; lblProcName, lblPID, lblRestricted: TLabel;
    pgTabs: TPageControl;
    tabMonitor, tabMemory: TTabSheet;
    pnlNetWrap, pnlNetHead: TPanel;
    lblNetTitle, lblNetCount: TLabel; edtNetSearch: TEdit; lvNet: TListView;
    pnlUrlWrap, pnlUrlHead: TPanel;
    lblUrlTitle, lblUrlCount: TLabel; edtUrlSearch: TEdit; lvURLs: TListView;
    pnlMemWrap, pnlMemHead: TPanel;
    lblMemTitle, lblMemCount: TLabel; edtMemSearch: TEdit; lvStrings: TListView;
    pnlRawHead: TPanel;
    lblRawTitle, lblRawCount: TLabel; edtRawSearch: TEdit; lblRawStatus: TLabel;
    lvRaw: TListView;
    pmCopy: TPopupMenu;
    tmrRefresh: TTimer;
    FProc: TProcessInfo; FExe: string; FMon: Boolean;
    FConns: TNetConnectionArray; FStrs: TExtractedStringArray;
    FConnKeys, FStrKeys: TStringList;
    FRawStrs: TRawMemStringArray;
    FRawFiltered: TRawMemStringArray;
    FRawScanned: Boolean;
    procedure Build;
    procedure BuildMonitorTab;
    procedure BuildMemoryTab;
    procedure OnTitleDown(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
    procedure OnTitleMove(S: TObject; Sh: TShiftState; X,Y: Integer);
    procedure OnTitleUp(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
    procedure OnTitleDbl(S: TObject);
    procedure OnCloseClick(S: TObject);
    procedure OnMinClick(S: TObject);
    procedure OnMaxClick(S: TObject);
    procedure OnBtnEnter(S: TObject);
    procedure OnBtnLeave(S: TObject);
    procedure DoToggleMax;
    procedure OnGripDown(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
    procedure OnDropClick(S: TObject);
    procedure OnLaunchClick(S: TObject);
    procedure OnStopClick(S: TObject);
    procedure OnSaveClick(S: TObject);
    procedure OnClearClick(S: TObject);
    procedure OnNewClick(S: TObject);
    procedure OnTimer(S: TObject);
    procedure OnNetSearch(S: TObject);
    procedure OnUrlSearch(S: TObject);
    procedure OnMemSearch(S: TObject);
    procedure OnRawSearch(S: TObject);
    procedure OnCopyClick(S: TObject);
    procedure WMDropFiles(var M: TWMDropFiles); message WM_DROPFILES;
    procedure SelFile(const P: string);
    procedure Fetch;
    procedure FetchRaw;
    procedure MergeConns(const New: TNetConnectionArray);
    procedure MergeStrs(const New: TExtractedStringArray);
    procedure FilterNet;
    procedure FilterUrl;
    procedure FilterMem;
    procedure FilterRaw;
    procedure PopulateRaw;
    procedure UpdInfo;
    procedure SetMon(A: Boolean);
    procedure ShowDrop(V: Boolean);
    procedure DoClear;
    procedure DoSave;
    function MakeHead(AP: TWinControl; const T: string; out LT,LC: TLabel; out E: TEdit; AOn: TNotifyEvent): TPanel;
    function MakeEdit(AP: TWinControl; AOn: TNotifyEvent): TEdit;
    procedure AttachPopup(LV: TListView);
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

const
  C_BG=$282828; C_TITLE=$1E1E1E; C_PANEL=$383838; C_HEAD=$303030;
  C_ACCENT=$C08040; C_TEXT=$E0E0E0; C_DIM=$909090; C_GREEN=$40C040;
  C_RED=$4040E0; C_URL=$F0A050; C_EDIT=$404040; C_HOVER=$505050;
  C_CLOSEH=$2020E0; TH=32; GS=5;

procedure TfrmMain.FormCreate(Sender: TObject);
var MI: TMenuItem;
begin
  Width:=1140; Height:=880; Position:=poScreenCenter;
  Color:=C_BG; Font.Name:='Segoe UI'; Font.Size:=9; Font.Color:=C_TEXT;
  FExe:=''; FMon:=False; FDrag:=False; FIsMax:=False; FRawScanned:=False;
  SetLength(FConns,0); SetLength(FStrs,0); SetLength(FRawStrs,0); SetLength(FRawFiltered,0);
  FConnKeys:=TStringList.Create; FConnKeys.Sorted:=True; FConnKeys.Duplicates:=dupIgnore;
  FStrKeys:=TStringList.Create; FStrKeys.Sorted:=True; FStrKeys.Duplicates:=dupIgnore;
  pmCopy:=TPopupMenu.Create(Self);
  MI:=TMenuItem.Create(pmCopy); MI.Caption:='Copy'; MI.OnClick:=OnCopyClick; pmCopy.Items.Add(MI);
  Build; DragAcceptFiles(Handle,True);
end;

procedure TfrmMain.FormDestroy(Sender: TObject);
begin
  DragAcceptFiles(Handle,False);
  if tmrRefresh<>nil then tmrRefresh.Enabled:=False;
  if FProc.IsRunning then KillProcess(FProc);
  CleanupProcess(FProc); FConnKeys.Free; FStrKeys.Free;
end;

procedure TfrmMain.WMDropFiles(var M: TWMDropFiles);
var B: array[0..MAX_PATH] of Char; F: string;
begin
  try if DragQueryFile(M.Drop,0,B,MAX_PATH)>0 then begin F:=B;
    if LowerCase(ExtractFileExt(F))='.exe' then SelFile(F)
    else MessageBox(Handle,'Drop an .exe file.','Invalid',MB_ICONWARNING); end;
  finally DragFinish(M.Drop); end; M.Result:=0;
end;

procedure TfrmMain.OnCopyClick(S: TObject);
var LV: TListView; LI: TListItem; Txt: string; I: Integer;
begin
  LV := nil;
  if (ActiveControl is TListView) then LV := TListView(ActiveControl);
  if LV = nil then Exit;
  LI := LV.Selected;
  if LI = nil then Exit;
  Txt := LI.Caption;
  for I := 0 to LI.SubItems.Count-1 do Txt := Txt + #9 + LI.SubItems[I];
  Clipboard.AsText := Txt;
end;

procedure TfrmMain.AttachPopup(LV: TListView);
begin
  LV.PopupMenu := pmCopy;
end;

procedure TfrmMain.Build;

  function CBtn(const Cap: string; L: Integer; AClick: TNotifyEvent): TLabel;
  begin
    Result:=TLabel.Create(Self); Result.Parent:=pnlTitle; Result.AutoSize:=False;
    Result.Width:=46; Result.Height:=TH; Result.Left:=L; Result.Top:=0;
    Result.Alignment:=taCenter; Result.Layout:=tlCenter;
    Result.Font.Name:='Segoe MDL2 Assets'; Result.Font.Size:=10;
    Result.Font.Color:=C_TEXT; Result.ParentFont:=False;
    Result.Transparent:=False; Result.Color:=C_TITLE; Result.Caption:=Cap;
    Result.Cursor:=crHandPoint; Result.Anchors:=[akTop,akRight];
    Result.OnClick:=AClick; Result.OnMouseEnter:=OnBtnEnter; Result.OnMouseLeave:=OnBtnLeave;
  end;

  function Grip(AA: TAlign; W,H: Integer; AC: TCursor): TPanel;
  begin
    Result:=TPanel.Create(Self); Result.Parent:=Self; Result.Align:=AA;
    Result.Width:=W; Result.Height:=H; Result.BevelOuter:=bvNone;
    Result.Color:=C_BG; Result.ParentColor:=False; Result.Cursor:=AC;
    Result.OnMouseDown:=OnGripDown;
  end;

begin
  pnlTitle:=TPanel.Create(Self); pnlTitle.Parent:=Self; pnlTitle.Align:=alTop;
  pnlTitle.Height:=TH; pnlTitle.BevelOuter:=bvNone; pnlTitle.Color:=C_TITLE;
  pnlTitle.ParentColor:=False;
  pnlTitle.OnMouseDown:=OnTitleDown; pnlTitle.OnMouseMove:=OnTitleMove;
  pnlTitle.OnMouseUp:=OnTitleUp; pnlTitle.OnDblClick:=OnTitleDbl;

  lblTitle:=TLabel.Create(Self); lblTitle.Parent:=pnlTitle;
  lblTitle.Left:=12; lblTitle.Top:=0; lblTitle.Height:=TH; lblTitle.Layout:=tlCenter;
  lblTitle.Font.Color:=C_ACCENT; lblTitle.Font.Size:=11; lblTitle.Font.Style:=[fsBold];
  lblTitle.ParentFont:=False; lblTitle.Transparent:=True; lblTitle.Caption:='MasonRadar';
  lblTitle.OnMouseDown:=OnTitleDown; lblTitle.OnMouseMove:=OnTitleMove;
  lblTitle.OnMouseUp:=OnTitleUp; lblTitle.OnDblClick:=OnTitleDbl;

  btnClose:=CBtn(#$E106,ClientWidth-46,OnCloseClick);
  btnMax:=CBtn(#$E922,ClientWidth-92,OnMaxClick);
  btnMin:=CBtn(#$E921,ClientWidth-138,OnMinClick);

  pnlGripR:=Grip(alRight,GS,0,crSizeWE); pnlGripB:=Grip(alBottom,0,GS,crSizeNS);
  pnlGripRB:=TPanel.Create(Self); pnlGripRB.Parent:=Self;
  pnlGripRB.Width:=GS*3; pnlGripRB.Height:=GS*3; pnlGripRB.BevelOuter:=bvNone;
  pnlGripRB.Color:=C_BG; pnlGripRB.ParentColor:=False; pnlGripRB.Cursor:=crSizeNWSE;
  pnlGripRB.Anchors:=[akRight,akBottom];
  pnlGripRB.Left:=ClientWidth-pnlGripRB.Width; pnlGripRB.Top:=ClientHeight-pnlGripRB.Height;
  pnlGripRB.OnMouseDown:=OnGripDown;

  pnlDrop:=TPanel.Create(Self); pnlDrop.Parent:=Self; pnlDrop.Align:=alClient;
  pnlDrop.BevelOuter:=bvNone; pnlDrop.Color:=C_BG; pnlDrop.ParentColor:=False;
  pnlDrop.Cursor:=crHandPoint; pnlDrop.OnClick:=OnDropClick;

  lblDropHint:=TLabel.Create(Self); lblDropHint.Parent:=pnlDrop;
  lblDropHint.AutoSize:=False; lblDropHint.Alignment:=taCenter; lblDropHint.Layout:=tlCenter;
  lblDropHint.WordWrap:=True; lblDropHint.Width:=500; lblDropHint.Height:=120;
  lblDropHint.Left:=(ClientWidth-500) div 2; lblDropHint.Top:=(ClientHeight-120) div 2;
  lblDropHint.Anchors:=[]; lblDropHint.Font.Name:='Segoe UI';
  lblDropHint.Font.Size:=20; lblDropHint.Font.Color:=C_DIM;
  lblDropHint.ParentFont:=False; lblDropHint.Transparent:=True;
  lblDropHint.Caption:='MasonRadar'#13#10#13#10'Drag && Drop .exe or click to browse';
  lblDropHint.Cursor:=crHandPoint; lblDropHint.OnClick:=OnDropClick;

  pnlToolbar:=TPanel.Create(Self); pnlToolbar.Parent:=Self; pnlToolbar.Align:=alTop;
  pnlToolbar.Height:=44; pnlToolbar.BevelOuter:=bvNone; pnlToolbar.Color:=C_PANEL;
  pnlToolbar.ParentColor:=False; pnlToolbar.Visible:=False;

  lblExePath:=TLabel.Create(Self); lblExePath.Parent:=pnlToolbar;
  lblExePath.Left:=12; lblExePath.Top:=13; lblExePath.Width:=430; lblExePath.AutoSize:=False;
  lblExePath.EllipsisPosition:=epPathEllipsis;
  lblExePath.Font.Color:=C_TEXT; lblExePath.Font.Size:=10; lblExePath.ParentFont:=False;

  btnLaunch:=TButton.Create(Self); btnLaunch.Parent:=pnlToolbar;
  btnLaunch.SetBounds(550,8,66,28); btnLaunch.Caption:='Launch';
  btnLaunch.Anchors:=[akTop,akRight]; btnLaunch.OnClick:=OnLaunchClick;

  btnStop:=TButton.Create(Self); btnStop.Parent:=pnlToolbar;
  btnStop.SetBounds(622,8,66,28); btnStop.Caption:='Stop'; btnStop.Enabled:=False;
  btnStop.Anchors:=[akTop,akRight]; btnStop.OnClick:=OnStopClick;

  btnSave:=TButton.Create(Self); btnSave.Parent:=pnlToolbar;
  btnSave.SetBounds(694,8,66,28); btnSave.Caption:='Save'; btnSave.Enabled:=False;
  btnSave.Anchors:=[akTop,akRight]; btnSave.OnClick:=OnSaveClick;

  btnClear:=TButton.Create(Self); btnClear.Parent:=pnlToolbar;
  btnClear.SetBounds(766,8,66,28); btnClear.Caption:='Clear'; btnClear.Enabled:=False;
  btnClear.Anchors:=[akTop,akRight]; btnClear.OnClick:=OnClearClick;

  btnNewFile:=TButton.Create(Self); btnNewFile.Parent:=pnlToolbar;
  btnNewFile.SetBounds(838,8,66,28); btnNewFile.Caption:='Open...';
  btnNewFile.Anchors:=[akTop,akRight]; btnNewFile.OnClick:=OnNewClick;

  lblStatus:=TLabel.Create(Self); lblStatus.Parent:=pnlToolbar;
  lblStatus.Left:=920; lblStatus.Top:=14; lblStatus.Width:=180;
  lblStatus.Font.Color:=C_DIM; lblStatus.Font.Size:=9; lblStatus.ParentFont:=False;
  lblStatus.Anchors:=[akTop,akRight];

  pnlInfo:=TPanel.Create(Self); pnlInfo.Parent:=Self; pnlInfo.Align:=alTop;
  pnlInfo.Height:=46; pnlInfo.BevelOuter:=bvNone; pnlInfo.Color:=C_BG;
  pnlInfo.ParentColor:=False; pnlInfo.Visible:=False;

  lblProcName:=TLabel.Create(Self); lblProcName.Parent:=pnlInfo;
  lblProcName.Left:=12; lblProcName.Top:=4; lblProcName.Font.Color:=C_TEXT;
  lblProcName.Font.Size:=10; lblProcName.Font.Style:=[fsBold]; lblProcName.ParentFont:=False;

  lblPID:=TLabel.Create(Self); lblPID.Parent:=pnlInfo;
  lblPID.Left:=12; lblPID.Top:=26; lblPID.Font.Color:=C_DIM; lblPID.ParentFont:=False;

  lblRestricted:=TLabel.Create(Self); lblRestricted.Parent:=pnlInfo;
  lblRestricted.Left:=220; lblRestricted.Top:=26; lblRestricted.Font.Color:=C_ACCENT;
  lblRestricted.ParentFont:=False;

  pgTabs:=TPageControl.Create(Self); pgTabs.Parent:=Self; pgTabs.Align:=alClient;
  pgTabs.Style:=tsButtons; pgTabs.Font.Color:=C_TEXT; pgTabs.ParentFont:=False;
  pgTabs.Visible:=False;

  tabMonitor:=TTabSheet.Create(pgTabs); tabMonitor.PageControl:=pgTabs;
  tabMonitor.Caption:='  Monitor  ';

  tabMemory:=TTabSheet.Create(pgTabs); tabMemory.PageControl:=pgTabs;
  tabMemory.Caption:='  Memory Explorer  ';

  BuildMonitorTab;
  BuildMemoryTab;

  pnlTitle.BringToFront;

  tmrRefresh:=TTimer.Create(Self); tmrRefresh.Interval:=3000;
  tmrRefresh.Enabled:=False; tmrRefresh.OnTimer:=OnTimer;

  ShowDrop(True);
end;

procedure TfrmMain.BuildMonitorTab;
begin
  pnlMemWrap:=TPanel.Create(Self); pnlMemWrap.Parent:=tabMonitor;
  pnlMemWrap.Align:=alClient; pnlMemWrap.BevelOuter:=bvNone;
  pnlMemWrap.Color:=C_BG; pnlMemWrap.ParentColor:=False;
  pnlMemHead:=MakeHead(pnlMemWrap,'Memory Strings (Domains / IPs)',lblMemTitle,lblMemCount,edtMemSearch,OnMemSearch);
  lvStrings:=TListView.Create(Self); lvStrings.Parent:=pnlMemWrap;
  lvStrings.Align:=alClient; lvStrings.ViewStyle:=vsReport;
  lvStrings.RowSelect:=True; lvStrings.GridLines:=True; lvStrings.ReadOnly:=True;
  lvStrings.Color:=C_PANEL; lvStrings.Font.Color:=C_TEXT; lvStrings.ParentFont:=False;
  with lvStrings.Columns.Add do begin Caption:='Category'; Width:=80; end;
  with lvStrings.Columns.Add do begin Caption:='Value'; Width:=540; end;
  with lvStrings.Columns.Add do begin Caption:='Address'; Width:=130; end;
  AttachPopup(lvStrings);

  pnlUrlWrap:=TPanel.Create(Self); pnlUrlWrap.Parent:=tabMonitor;
  pnlUrlWrap.Align:=alTop; pnlUrlWrap.Height:=165; pnlUrlWrap.BevelOuter:=bvNone;
  pnlUrlWrap.Color:=C_BG; pnlUrlWrap.ParentColor:=False;
  pnlUrlHead:=MakeHead(pnlUrlWrap,'URLs / Links',lblUrlTitle,lblUrlCount,edtUrlSearch,OnUrlSearch);
  lvURLs:=TListView.Create(Self); lvURLs.Parent:=pnlUrlWrap;
  lvURLs.Align:=alClient; lvURLs.ViewStyle:=vsReport;
  lvURLs.RowSelect:=True; lvURLs.GridLines:=True; lvURLs.ReadOnly:=True;
  lvURLs.Color:=C_PANEL; lvURLs.Font.Color:=C_URL; lvURLs.ParentFont:=False;
  with lvURLs.Columns.Add do begin Caption:='URL'; Width:=660; end;
  with lvURLs.Columns.Add do begin Caption:='Address'; Width:=130; end;
  AttachPopup(lvURLs);

  pnlNetWrap:=TPanel.Create(Self); pnlNetWrap.Parent:=tabMonitor;
  pnlNetWrap.Align:=alTop; pnlNetWrap.Height:=195; pnlNetWrap.BevelOuter:=bvNone;
  pnlNetWrap.Color:=C_BG; pnlNetWrap.ParentColor:=False;
  pnlNetHead:=MakeHead(pnlNetWrap,'Network Connections',lblNetTitle,lblNetCount,edtNetSearch,OnNetSearch);
  lvNet:=TListView.Create(Self); lvNet.Parent:=pnlNetWrap;
  lvNet.Align:=alClient; lvNet.ViewStyle:=vsReport;
  lvNet.RowSelect:=True; lvNet.GridLines:=True; lvNet.ReadOnly:=True;
  lvNet.Color:=C_PANEL; lvNet.Font.Color:=C_TEXT; lvNet.ParentFont:=False;
  with lvNet.Columns.Add do begin Caption:='Protocol'; Width:=60; end;
  with lvNet.Columns.Add do begin Caption:='Detection'; Width:=95; end;
  with lvNet.Columns.Add do begin Caption:='Local IP'; Width:=120; end;
  with lvNet.Columns.Add do begin Caption:='Local Port'; Width:=72; end;
  with lvNet.Columns.Add do begin Caption:='Remote IP'; Width:=120; end;
  with lvNet.Columns.Add do begin Caption:='Remote Port'; Width:=82; end;
  with lvNet.Columns.Add do begin Caption:='State'; Width:=100; end;
  AttachPopup(lvNet);
end;

procedure TfrmMain.BuildMemoryTab;
begin
  pnlRawHead:=TPanel.Create(Self); pnlRawHead.Parent:=tabMemory;
  pnlRawHead.Align:=alTop; pnlRawHead.Height:=38; pnlRawHead.BevelOuter:=bvNone;
  pnlRawHead.Color:=C_HEAD; pnlRawHead.ParentColor:=False;

  lblRawTitle:=TLabel.Create(Self); lblRawTitle.Parent:=pnlRawHead;
  lblRawTitle.Left:=10; lblRawTitle.Top:=10;
  lblRawTitle.Font.Color:=C_TEXT; lblRawTitle.Font.Size:=9; lblRawTitle.Font.Style:=[fsBold];
  lblRawTitle.ParentFont:=False; lblRawTitle.Caption:='Full Memory Strings';

  lblRawCount:=TLabel.Create(Self); lblRawCount.Parent:=pnlRawHead;
  lblRawCount.Left:=170; lblRawCount.Top:=11;
  lblRawCount.Font.Color:=C_DIM; lblRawCount.Font.Size:=8; lblRawCount.ParentFont:=False;
  lblRawCount.Caption:='(0)';

  lblRawStatus:=TLabel.Create(Self); lblRawStatus.Parent:=pnlRawHead;
  lblRawStatus.Left:=260; lblRawStatus.Top:=11;
  lblRawStatus.Font.Color:=C_DIM; lblRawStatus.Font.Size:=8; lblRawStatus.ParentFont:=False;

  edtRawSearch:=MakeEdit(pnlRawHead,OnRawSearch);
  edtRawSearch.Top:=8;

  lvRaw:=TListView.Create(Self); lvRaw.Parent:=tabMemory;
  lvRaw.Align:=alClient; lvRaw.ViewStyle:=vsReport;
  lvRaw.RowSelect:=True; lvRaw.GridLines:=True; lvRaw.ReadOnly:=True;
  lvRaw.Color:=C_PANEL; lvRaw.Font.Color:=C_TEXT; lvRaw.Font.Size:=8;
  lvRaw.ParentFont:=False;
  with lvRaw.Columns.Add do begin Caption:='#'; Width:=55; end;
  with lvRaw.Columns.Add do begin Caption:='Address'; Width:=100; end;
  with lvRaw.Columns.Add do begin Caption:='Len'; Width:=50; end;
  with lvRaw.Columns.Add do begin Caption:='Enc'; Width:=55; end;
  with lvRaw.Columns.Add do begin Caption:='Prot'; Width:=45; end;
  with lvRaw.Columns.Add do begin Caption:='Value'; Width:=700; end;
  AttachPopup(lvRaw);
end;

function TfrmMain.MakeHead(AP: TWinControl; const T: string;
  out LT,LC: TLabel; out E: TEdit; AOn: TNotifyEvent): TPanel;
begin
  Result:=TPanel.Create(Self); Result.Parent:=AP; Result.Align:=alTop;
  Result.Height:=30; Result.BevelOuter:=bvNone; Result.Color:=C_HEAD; Result.ParentColor:=False;
  LT:=TLabel.Create(Self); LT.Parent:=Result; LT.Left:=10; LT.Top:=6;
  LT.Font.Color:=C_TEXT; LT.Font.Size:=9; LT.Font.Style:=[fsBold]; LT.ParentFont:=False; LT.Caption:=T;
  LC:=TLabel.Create(Self); LC.Parent:=Result;
  LC.Left:=10+LT.Canvas.TextWidth(T)+10; LC.Top:=7;
  LC.Font.Color:=C_DIM; LC.Font.Size:=8; LC.ParentFont:=False; LC.Caption:='(0)';
  E:=MakeEdit(Result,AOn);
end;

function TfrmMain.MakeEdit(AP: TWinControl; AOn: TNotifyEvent): TEdit;
begin
  Result:=TEdit.Create(Self); Result.Parent:=AP;
  Result.Width:=220; Result.Height:=22; Result.Top:=4;
  Result.Left:=AP.Width-232; Result.Anchors:=[akTop,akRight];
  Result.Font.Color:=C_TEXT; Result.Font.Size:=9; Result.Color:=C_EDIT;
  Result.ParentFont:=False; Result.TextHint:='Search...'; Result.OnChange:=AOn;
end;

procedure TfrmMain.OnBtnEnter(S: TObject); begin if S=btnClose then TLabel(S).Color:=C_CLOSEH else TLabel(S).Color:=C_HOVER; end;
procedure TfrmMain.OnBtnLeave(S: TObject); begin TLabel(S).Color:=C_TITLE; end;
procedure TfrmMain.OnCloseClick(S: TObject); begin Close; end;
procedure TfrmMain.OnMinClick(S: TObject); begin Application.Minimize; end;
procedure TfrmMain.OnMaxClick(S: TObject); begin DoToggleMax; end;

procedure TfrmMain.DoToggleMax;
var R: TRect;
begin if FIsMax then begin SetBounds(FRestore.Left,FRestore.Top,FRestore.Width,FRestore.Height); FIsMax:=False; end
  else begin FRestore:=BoundsRect; R:=Screen.WorkAreaRect; SetBounds(R.Left,R.Top,R.Width,R.Height); FIsMax:=True; end; end;

procedure TfrmMain.OnTitleDown(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
begin if B=mbLeft then begin FDrag:=True; FDragPt.X:=Mouse.CursorPos.X-Left; FDragPt.Y:=Mouse.CursorPos.Y-Top; end; end;

procedure TfrmMain.OnTitleMove(S: TObject; Sh: TShiftState; X,Y: Integer);
begin if FDrag then begin if FIsMax then begin FIsMax:=False; Width:=FRestore.Width; Height:=FRestore.Height;
  FDragPt.X:=Width div 2; FDragPt.Y:=TH div 2; end;
  Left:=Mouse.CursorPos.X-FDragPt.X; Top:=Mouse.CursorPos.Y-FDragPt.Y; end; end;

procedure TfrmMain.OnTitleUp(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
begin FDrag:=False; end;

procedure TfrmMain.OnTitleDbl(S: TObject); begin DoToggleMax; end;

procedure TfrmMain.OnGripDown(S: TObject; B: TMouseButton; Sh: TShiftState; X,Y: Integer);
begin if B<>mbLeft then Exit; ReleaseCapture;
  if S=pnlGripR then Perform(WM_SYSCOMMAND,$F002,0) else if S=pnlGripB then Perform(WM_SYSCOMMAND,$F006,0)
  else Perform(WM_SYSCOMMAND,$F008,0); end;

procedure TfrmMain.OnDropClick(S: TObject);
var D: TOpenDialog;
begin D:=TOpenDialog.Create(Self);
  try D.Filter:='Executables (*.exe)|*.exe|All (*.*)|*.*'; D.Title:='Select executable';
    if D.Execute then SelFile(D.FileName); finally D.Free; end; end;

procedure TfrmMain.OnNewClick(S: TObject); begin OnDropClick(S); end;

procedure TfrmMain.SelFile(const P: string);
begin
  if FMon then begin SetMon(False); KillProcess(FProc); CleanupProcess(FProc); end;
  FExe:=P; lblExePath.Caption:=FExe; btnLaunch.Enabled:=True; btnStop.Enabled:=False;
  btnSave.Enabled:=False; btnClear.Enabled:=False;
  lblStatus.Caption:='Ready'; lblStatus.Font.Color:=C_DIM; DoClear; ShowDrop(False);
end;

procedure TfrmMain.OnLaunchClick(S: TObject);
begin
  if FExe='' then Exit;
  if FProc.hProcess<>0 then begin KillProcess(FProc); CleanupProcess(FProc); end;
  DoClear;
  if not LaunchProcess(FExe,FProc) then begin
    MessageBox(Handle,PChar('Failed:'#13#10+FProc.ErrorMsg),'Error',MB_ICONERROR); Exit; end;
  UpdInfo; SetMon(True); btnSave.Enabled:=True; btnClear.Enabled:=True;
end;

procedure TfrmMain.OnStopClick(S: TObject);
begin SetMon(False); KillProcess(FProc); CleanupProcess(FProc);
  lblStatus.Caption:='Stopped'; lblStatus.Font.Color:=C_RED;
  btnStop.Enabled:=False; btnLaunch.Enabled:=(FExe<>''); end;

procedure TfrmMain.OnClearClick(S: TObject);
begin DoClear; FilterNet; FilterUrl; FilterMem; end;

procedure TfrmMain.OnSaveClick(S: TObject); begin DoSave; end;

procedure TfrmMain.OnTimer(S: TObject);
begin
  if not IsProcessAlive(FProc) then begin SetMon(False); lblStatus.Caption:='Exited';
    lblStatus.Font.Color:=C_RED; btnStop.Enabled:=False; btnLaunch.Enabled:=(FExe<>'');
    CleanupProcess(FProc); Exit; end;
  Fetch;
end;

procedure TfrmMain.Fetch;
begin
  MergeConns(GetConnectionsForPID(FProc.PID));
  MergeStrs(ScanProcessMemory(FProc.PID));
  FilterNet; FilterUrl; FilterMem;
  FetchRaw;
end;

procedure TfrmMain.FetchRaw;
var NewRaw: TRawMemStringArray; I,X: Integer; Seen: TStringList;
begin
  if FProc.PID = 0 then Exit;
  NewRaw := ScanProcessMemoryFull(FProc.PID, 4);
  Seen := TStringList.Create;
  try
    Seen.Sorted := True; Seen.Duplicates := dupIgnore;
    for I := 0 to High(FRawStrs) do Seen.Add(FRawStrs[I].Value);
    for I := 0 to High(NewRaw) do begin
      if Seen.IndexOf(NewRaw[I].Value) >= 0 then Continue;
      Seen.Add(NewRaw[I].Value);
      X := Length(FRawStrs); SetLength(FRawStrs, X+1); FRawStrs[X] := NewRaw[I];
    end;
  finally Seen.Free; end;
  FRawScanned := True;
  FilterRaw;
end;

procedure TfrmMain.MergeConns(const New: TNetConnectionArray);
var I,X: Integer; Key: string;
begin
  for I:=0 to High(New) do begin
    Key:=New[I].Protocol+'|'+New[I].LocalAddr+':'+IntToStr(New[I].LocalPort)+
         '|'+New[I].RemoteAddr+':'+IntToStr(New[I].RemotePort);
    if FConnKeys.IndexOf(Key)>=0 then begin
      for X:=0 to High(FConns) do
        if (FConns[X].LocalAddr=New[I].LocalAddr) and (FConns[X].LocalPort=New[I].LocalPort) and
           (FConns[X].RemoteAddr=New[I].RemoteAddr) and (FConns[X].RemotePort=New[I].RemotePort) then
        begin FConns[X].State:=New[I].State; Break; end;
      Continue; end;
    FConnKeys.Add(Key); X:=Length(FConns); SetLength(FConns,X+1); FConns[X]:=New[I];
  end;
end;

procedure TfrmMain.MergeStrs(const New: TExtractedStringArray);
var I,X: Integer;
begin
  for I:=0 to High(New) do begin
    if FStrKeys.IndexOf(New[I].Value)>=0 then Continue;
    FStrKeys.Add(New[I].Value); X:=Length(FStrs); SetLength(FStrs,X+1); FStrs[X]:=New[I];
  end;
end;

procedure TfrmMain.OnNetSearch(S: TObject); begin FilterNet; end;
procedure TfrmMain.OnUrlSearch(S: TObject); begin FilterUrl; end;
procedure TfrmMain.OnMemSearch(S: TObject); begin FilterMem; end;
procedure TfrmMain.OnRawSearch(S: TObject); begin FilterRaw; end;

procedure TfrmMain.FilterNet;
var I,N: Integer; LI: TListItem; F,Row: string;
begin F:=LowerCase(Trim(edtNetSearch.Text)); N:=0;
  lvNet.Items.BeginUpdate; try lvNet.Items.Clear;
    for I:=0 to High(FConns) do begin
      Row:=LowerCase(FConns[I].Protocol+' '+FConns[I].Detection+' '+FConns[I].LocalAddr+' '+
        IntToStr(FConns[I].LocalPort)+' '+FConns[I].RemoteAddr+' '+IntToStr(FConns[I].RemotePort)+' '+FConns[I].State);
      if (F<>'') and (Pos(F,Row)=0) then Continue;
      LI:=lvNet.Items.Add; LI.Caption:=FConns[I].Protocol;
      LI.SubItems.Add(FConns[I].Detection); LI.SubItems.Add(FConns[I].LocalAddr);
      LI.SubItems.Add(IntToStr(FConns[I].LocalPort)); LI.SubItems.Add(FConns[I].RemoteAddr);
      if FConns[I].RemotePort>0 then LI.SubItems.Add(IntToStr(FConns[I].RemotePort)) else LI.SubItems.Add('*');
      LI.SubItems.Add(FConns[I].State); Inc(N);
    end; finally lvNet.Items.EndUpdate; end;
  lblNetCount.Caption:=Format('(%d/%d)',[N,Length(FConns)]);
end;

procedure TfrmMain.FilterUrl;
var I,N: Integer; LI: TListItem; F: string; Seen: TStringList;
begin F:=LowerCase(Trim(edtUrlSearch.Text)); N:=0;
  Seen:=TStringList.Create; try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore;
    lvURLs.Items.BeginUpdate; try lvURLs.Items.Clear;
      for I:=0 to High(FStrs) do begin
        if FStrs[I].Category<>scURL then Continue;
        if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
        if (F<>'') and (Pos(F,LowerCase(FStrs[I].Value))=0) then Continue;
        LI:=lvURLs.Items.Add; LI.Caption:=FStrs[I].Value;
        LI.SubItems.Add(Format('0x%x',[FStrs[I].Address])); Inc(N);
      end; finally lvURLs.Items.EndUpdate; end;
  finally Seen.Free; end;
  lblUrlCount.Caption:=Format('(%d)',[N]);
end;

procedure TfrmMain.FilterMem;
var I,N: Integer; LI: TListItem; F,CS: string; Seen: TStringList;
begin F:=LowerCase(Trim(edtMemSearch.Text)); N:=0;
  Seen:=TStringList.Create; try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore;
    lvStrings.Items.BeginUpdate; try lvStrings.Items.Clear;
      for I:=0 to High(FStrs) do begin
        if FStrs[I].Category=scURL then Continue;
        if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
        CS:=CategoryLabel(FStrs[I].Category);
        if (F<>'') and (Pos(F,LowerCase(CS+' '+FStrs[I].Value))=0) then Continue;
        LI:=lvStrings.Items.Add; LI.Caption:=CS; LI.SubItems.Add(FStrs[I].Value);
        LI.SubItems.Add(Format('0x%x',[FStrs[I].Address])); Inc(N);
      end; finally lvStrings.Items.EndUpdate; end;
  finally Seen.Free; end;
  lblMemCount.Caption:=Format('(%d)',[N]);
end;

procedure TfrmMain.FilterRaw;
var I,N: Integer; F: string;
begin
  F:=LowerCase(Trim(edtRawSearch.Text)); N:=0;
  SetLength(FRawFiltered, 0);
  for I:=0 to High(FRawStrs) do begin
    if (F<>'') and (Pos(F,LowerCase(FRawStrs[I].Value))=0) then Continue;
    SetLength(FRawFiltered, N+1); FRawFiltered[N] := FRawStrs[I]; Inc(N);
  end;
  lblRawCount.Caption:=Format('(%d/%d)',[N,Length(FRawStrs)]);
  if FRawScanned then
    lblRawStatus.Caption:=Format('Total: %d',[Length(FRawStrs)]);
  PopulateRaw;
end;

procedure TfrmMain.PopulateRaw;
var I,Max: Integer; LI: TListItem;
begin
  Max := 30000;
  lvRaw.Items.BeginUpdate;
  try lvRaw.Items.Clear;
    for I:=0 to High(FRawFiltered) do begin
      if I>=Max then Break;
      LI:=lvRaw.Items.Add;
      LI.Caption:=IntToStr(I+1);
      LI.SubItems.Add(Format('0x%x',[FRawFiltered[I].Address]));
      LI.SubItems.Add(IntToStr(FRawFiltered[I].Len));
      LI.SubItems.Add(FRawFiltered[I].Encoding);
      LI.SubItems.Add(FRawFiltered[I].Protect);
      LI.SubItems.Add(FRawFiltered[I].Value);
    end;
  finally lvRaw.Items.EndUpdate; end;
end;

procedure TfrmMain.DoSave;
var D: TSaveDialog; SL,Seen: TStringList; I: Integer; FN: string;
begin
  FN := 'MasonRadar_'+FormatDateTime('yyyymmdd_hhnnss',Now)+'.txt';
  D:=TSaveDialog.Create(Self);
  try
    D.Filter:='Text files (*.txt)|*.txt|All files (*.*)|*.*';
    D.DefaultExt:='txt';
    D.FileName:=FN;
    D.Options:=D.Options+[ofOverwritePrompt];
    if not D.Execute then Exit;
    FN := D.FileName;
  finally D.Free; end;
  if FN='' then Exit;
  SL:=TStringList.Create; Seen:=TStringList.Create;
  try Seen.Sorted:=True; Seen.Duplicates:=dupIgnore;
    SL.Add('=== MasonRadar Report ===');
    SL.Add('Date: '+DateTimeToStr(Now));
    SL.Add('Process: '+ExtractFileName(FExe));
    SL.Add('Path: '+FExe);
    SL.Add('PID: '+IntToStr(FProc.PID));
    SL.Add('');
    SL.Add('--- Network ('+IntToStr(Length(FConns))+') ---');
    SL.Add('');
    for I:=0 to High(FConns) do
      SL.Add(Format('  %-5s %-11s %-16s:%-5d -> %-16s:%-5d %s',
        [FConns[I].Protocol,FConns[I].Detection,FConns[I].LocalAddr,FConns[I].LocalPort,
         FConns[I].RemoteAddr,FConns[I].RemotePort,FConns[I].State]));
    SL.Add('');
    SL.Add('--- URLs ---');
    SL.Add('');
    Seen.Clear;
    for I:=0 to High(FStrs) do begin
      if FStrs[I].Category<>scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
      SL.Add('  '+FStrs[I].Value);
    end;
    SL.Add('');
    SL.Add('--- Domains / IPs ---');
    SL.Add('');
    Seen.Clear;
    for I:=0 to High(FStrs) do begin
      if FStrs[I].Category=scURL then Continue;
      if Seen.IndexOf(FStrs[I].Value)>=0 then Continue; Seen.Add(FStrs[I].Value);
      SL.Add(Format('  [%-8s] %s',[CategoryLabel(FStrs[I].Category),FStrs[I].Value]));
    end;
    SL.Add('');
    SL.Add('=== End of Report ===');
    try
      SL.SaveToFile(FN);
      lblStatus.Caption:='Saved!'; lblStatus.Font.Color:=C_GREEN;
    except
      on E: Exception do
        MessageBox(Handle,PChar('Save failed: '+E.Message),'Error',MB_ICONERROR);
    end;
  finally Seen.Free; SL.Free; end;
end;

procedure TfrmMain.UpdInfo;
begin lblProcName.Caption:='Process: '+ExtractFileName(FProc.ExePath);
  lblPID.Caption:='PID: '+IntToStr(FProc.PID);
  if FProc.UsedRestricted then lblRestricted.Caption:='[Restricted / Low-Integrity Token]'
  else lblRestricted.Caption:='[Standard Token]'; end;

procedure TfrmMain.SetMon(A: Boolean);
begin FMon:=A; tmrRefresh.Enabled:=A; btnStop.Enabled:=A; btnLaunch.Enabled:=not A;
  if A then begin lblStatus.Caption:='Monitoring...'; lblStatus.Font.Color:=C_GREEN; Fetch; end; end;

procedure TfrmMain.ShowDrop(V: Boolean);
begin pnlDrop.Visible:=V; pnlToolbar.Visible:=not V; pnlInfo.Visible:=not V; pgTabs.Visible:=not V;
  if V then begin lblDropHint.Left:=(pnlDrop.ClientWidth-lblDropHint.Width) div 2;
    lblDropHint.Top:=(pnlDrop.ClientHeight-lblDropHint.Height) div 2; end; end;

procedure TfrmMain.DoClear;
begin
  SetLength(FConns,0); SetLength(FStrs,0); SetLength(FRawStrs,0); SetLength(FRawFiltered,0);
  FConnKeys.Clear; FStrKeys.Clear; FRawScanned:=False;
  if lvNet<>nil then lvNet.Items.Clear;
  if lvURLs<>nil then lvURLs.Items.Clear;
  if lvStrings<>nil then lvStrings.Items.Clear;
  if lvRaw<>nil then lvRaw.Items.Clear;
  if lblNetCount<>nil then lblNetCount.Caption:='(0)';
  if lblUrlCount<>nil then lblUrlCount.Caption:='(0)';
  if lblMemCount<>nil then lblMemCount.Caption:='(0)';
  if lblRawCount<>nil then lblRawCount.Caption:='(0)';
  if edtNetSearch<>nil then edtNetSearch.Text:='';
  if edtUrlSearch<>nil then edtUrlSearch.Text:='';
  if edtMemSearch<>nil then edtMemSearch.Text:='';
  if edtRawSearch<>nil then edtRawSearch.Text:='';
  if lblRawStatus<>nil then lblRawStatus.Caption:='';
  lblProcName.Caption:=''; lblPID.Caption:=''; lblRestricted.Caption:='';
end;

end.
