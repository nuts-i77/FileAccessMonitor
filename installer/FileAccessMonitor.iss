; Inno Setup 6 script. Build with build-installer.ps1 (runs build.ps1 first).
;   ISCC.exe /DAppVersion=1.2.3 installer\FileAccessMonitor.iss
; Silent install:
;   FileAccessMonitor-Setup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES /TASKS=firewall /PORT=8080

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "File Access Monitor"
#define AppExe "FileAccessMonitor.exe"

[Setup]
; Never change AppId: it links upgrades and the uninstaller to earlier installs.
AppId={{77312AEE-E529-4497-BDFA-6EF2437FA82E}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=FileAccessMonitor contributors
AppPublisherURL=https://github.com/nuts-i77/FileAccessMonitor
AppSupportURL=https://github.com/nuts-i77/FileAccessMonitor/issues
DefaultDirName={autopf}\FileAccessMonitor
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=FileAccessMonitor-Setup-{#AppVersion}
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ja"; MessagesFile: "compiler:Languages\Japanese.isl"

[CustomMessages]
en.PortCaption=Web GUI port
en.PortDescription=Choose the TCP port for the web GUI.
en.PortPrompt=Port (1-65535):
en.PortInvalid=Enter a port number between 1 and 65535.
en.FirewallTask=Allow the port through Windows Firewall (inbound TCP)
en.InstallingService=Registering and starting the service...
en.ServiceFailed=Failed to register or start the service (exit code %1).%nSee the application log in C:\ProgramData\FileAccessMonitor\logs.
en.OpenGui=Open the web GUI
en.ShowPassword=Show the initial admin password
en.FinishInfo=Sign in as "admin". The initial password is saved in:%n%1%n%nAfter signing in, add folders to monitor on the Settings tab.
en.UninstallKeptData=Access records, settings and keys were kept in:%n%1%n%nDelete that folder if you no longer need them. Audit entries (SACL) on monitored folders were not removed; use restore-audit.ps1 to remove them.
ja.PortCaption=Web GUI のポート
ja.PortDescription=Web GUI で使う TCP ポートを指定します。
ja.PortPrompt=ポート番号 (1-65535):
ja.PortInvalid=1 から 65535 までのポート番号を入力してください。
ja.FirewallTask=Windows ファイアウォールでこのポートの受信を許可する (TCP)
ja.InstallingService=サービスを登録・起動しています...
ja.ServiceFailed=サービスの登録または起動に失敗しました (終了コード %1)。%nC:\ProgramData\FileAccessMonitor\logs のログを確認してください。
ja.OpenGui=Web GUI を開く
ja.ShowPassword=初期管理者パスワードを表示する
ja.FinishInfo=ユーザー名「admin」でログインしてください。初期パスワードは次のファイルに保存されています。%n%1%n%nログイン後、「設定」タブで監視するフォルダを追加してください。
ja.UninstallKeptData=アクセス記録・設定・鍵は次のフォルダに残してあります。%n%1%n%n不要であれば削除してください。監視フォルダの監査エントリ (SACL) は削除していません。削除する場合は restore-audit.ps1 を使用してください。

[Tasks]
Name: "firewall"; Description: "{cm:FirewallTask}"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Excludes: "*.pdb,web.config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\setup-audit.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\restore-audit.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.ja.md"; DestDir: "{app}"; Flags: ignoreversion

[UninstallDelete]
Type: files; Name: "{app}\appsettings.Production.json"

[Run]
Filename: "http://localhost:{code:GetPort}/"; Description: "{cm:OpenGui}"; Flags: postinstall shellexec nowait skipifsilent
Filename: "{sys}\notepad.exe"; Parameters: """{code:GetPasswordFile}"""; Description: "{cm:ShowPassword}"; Flags: postinstall nowait skipifsilent unchecked; Check: PasswordFileExists

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\service.ps1"" -Action Uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
var
  PortPage: TInputQueryWizardPage;
  PreviousPort: String;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\FileAccessMonitor');
end;

function GetPasswordFile(Param: String): String;
begin
  Result := DataDir() + '\initial-admin-password.txt';
end;

function PasswordFileExists(): Boolean;
begin
  Result := FileExists(GetPasswordFile(''));
end;

function GetPort(Param: String): String;
begin
  Result := Trim(PortPage.Values[0]);
end;

function RunServiceScript(Args: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\service.ps1') + '" ' + Args,
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Result := ResultCode;
end;

procedure InitializeWizard();
begin
  PreviousPort := GetPreviousData('Port', '8080');
  PortPage := CreateInputQueryPage(wpSelectDir, CustomMessage('PortCaption'), CustomMessage('PortDescription'), '');
  PortPage.Add(CustomMessage('PortPrompt'), False);
  // Silent installs can pass /PORT=nnnn
  PortPage.Values[0] := ExpandConstant('{param:PORT|' + PreviousPort + '}');
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'Port', GetPort(''));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Port: Integer;
begin
  Result := True;
  if CurPageID = PortPage.ID then
  begin
    Port := StrToIntDef(GetPort(''), 0);
    if (Port < 1) or (Port > 65535) then
    begin
      MsgBox(CustomMessage('PortInvalid'), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

// The single-file exe is locked while the service runs, so stop it before files are replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if FileExists(ExpandConstant('{app}\service.ps1')) then
    RunServiceScript('-Action Stop');
  Result := '';
end;

// Keep user edits in appsettings.Production.json; only the listen URL is managed here.
procedure WritePortSetting();
var
  FileName, NewUrl: String;
  Content: AnsiString;
  Text: String;
begin
  FileName := ExpandConstant('{app}\appsettings.Production.json');
  NewUrl := 'http://0.0.0.0:' + GetPort('');
  if FileExists(FileName) and LoadStringFromFile(FileName, Content) then
  begin
    Text := String(Content);
    if StringChangeEx(Text, 'http://0.0.0.0:' + PreviousPort, NewUrl, True) > 0 then
      SaveStringToFile(FileName, AnsiString(Text), False);
  end
  else
    SaveStringToFile(FileName,
      '{' + #13#10 +
      '  "Kestrel": { "Endpoints": { "Http": { "Url": "' + NewUrl + '" } } }' + #13#10 +
      '}' + #13#10, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Args: String;
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WritePortSetting();
    WizardForm.StatusLabel.Caption := CustomMessage('InstallingService');
    Args := '-Action Install -Port ' + GetPort('');
    if WizardIsTaskSelected('firewall') then
      Args := Args + ' -Firewall';
    Code := RunServiceScript(Args);
    if Code <> 0 then
      MsgBox(FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(Code)]), mbError, MB_OK)
    else
      Sleep(3000);  // give the service time to create the initial admin password file
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
    WizardForm.FinishedLabel.Caption := FmtMessage(CustomMessage('FinishInfo'), [GetPasswordFile('')]);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and DirExists(DataDir()) and not UninstallSilent() then
    MsgBox(FmtMessage(CustomMessage('UninstallKeptData'), [DataDir()]), mbInformation, MB_OK);
end;
