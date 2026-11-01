; Inno Setup 6 script. Build with build-installer.ps1 (runs build.ps1 first).
;   ISCC.exe /DAppVersion=1.2.3 installer\FileAccessMonitor.iss
; Silent install:
;   FileAccessMonitor-Setup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES /TASKS=firewall /PORT=8080
; Silent install as an agent (connection string from Settings > Agents on the monitoring server):
;   FileAccessMonitor-Setup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES /ROLE=agent /CONNECTION=FAM1.xxxx

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
en.FirewallTask=Allow FileAccessMonitor through Windows Firewall (inbound: the web GUI port, and port 8443 for agents)
en.InstallingService=Registering and starting the service...
en.ServiceFailed=Failed to register or start the service (exit code %1).%nSee the application log in C:\ProgramData\FileAccessMonitor\logs.
en.OpenGui=Open the web GUI
en.ShowPassword=Show the initial admin password
en.FinishInfo=Sign in as "admin". The initial password is saved in:%n%1%n%nAfter signing in, add folders to monitor on the Settings tab.
en.UninstallKeptData=Access records, settings and keys were kept in:%n%1%n%nDelete that folder if you no longer need them. Audit entries (SACL) on monitored folders were not removed; use restore-audit.ps1 to remove them.
en.RoleCaption=Installation type
en.RoleDescription=Choose how this server is used.
en.RoleFull=Standalone / monitoring server: collect on this server and show the web GUI (other file servers can send their records here as agents)
en.RoleAgent=Agent: send this file server's access records to a monitoring server (no web GUI on this server)
en.ConnCaption=Monitoring server
en.ConnDescription=Paste the connection string issued under Settings > Agents on the monitoring server. It is valid for 24 hours and can be used once.
en.ConnPrompt=Connection string:
en.ConnInvalid=Paste the connection string that starts with FAM1. from the monitoring server.
en.Enrolling=Registering with the monitoring server...
en.EnrollFailed=Registration with the monitoring server failed:%n%n%1%nIssue a new connection string on the monitoring server and run the installer again.
en.AgentFinishInfo=This server now sends its access records to the monitoring server. Set up auditing of the shared folders in an elevated PowerShell with:%npowershell -ExecutionPolicy Bypass -File "%1\scripts\setup-audit.ps1" -SharePaths "D:\Share"
ja.PortCaption=Web GUI のポート
ja.PortDescription=Web GUI で使う TCP ポートを指定します。
ja.PortPrompt=ポート番号 (1-65535):
ja.PortInvalid=1 から 65535 までのポート番号を入力してください。
ja.FirewallTask=Windows ファイアウォールで FileAccessMonitor の受信を許可する（Web GUI のポートと、エージェント用ポート 8443）
ja.InstallingService=サービスを登録・起動しています...
ja.ServiceFailed=サービスの登録または起動に失敗しました (終了コード %1)。%nC:\ProgramData\FileAccessMonitor\logs のログを確認してください。
ja.OpenGui=Web GUI を開く
ja.ShowPassword=初期管理者パスワードを表示する
ja.FinishInfo=ユーザー名「admin」でログインしてください。初期パスワードは次のファイルに保存されています。%n%1%n%nログイン後、「設定」タブで監視するフォルダを追加してください。
ja.UninstallKeptData=アクセス記録・設定・鍵は次のフォルダに残してあります。%n%1%n%n不要であれば削除してください。監視フォルダの監査エントリ (SACL) は削除していません。削除する場合は restore-audit.ps1 を使用してください。
ja.RoleCaption=インストールの種類
ja.RoleDescription=このサーバーの使い方を選んでください。
ja.RoleFull=1 台構成 / 監視サーバー: このサーバーで収集し、Web GUI を表示します（他のファイルサーバーからエージェントとして記録を受け取ることもできます）
ja.RoleAgent=エージェント: このファイルサーバーのアクセス記録を監視サーバーに送ります（このサーバーには Web GUI を置きません）
ja.ConnCaption=監視サーバー
ja.ConnDescription=監視サーバーの「設定 > エージェント」で発行した接続文字列を貼り付けてください。24 時間有効で、1 回だけ使えます。
ja.ConnPrompt=接続文字列:
ja.ConnInvalid=監視サーバーで発行した、FAM1. で始まる接続文字列を貼り付けてください。
ja.Enrolling=監視サーバーに登録しています...
ja.EnrollFailed=監視サーバーへの登録に失敗しました:%n%n%1%n監視サーバーで接続文字列を発行し直して、インストーラーをもう一度実行してください。
ja.AgentFinishInfo=このサーバーのアクセス記録を監視サーバーに送るようになりました。共有フォルダの監査は、管理者 PowerShell で次を実行して設定してください。%npowershell -ExecutionPolicy Bypass -File "%1\scripts\setup-audit.ps1" -SharePaths "D:\Share"

[Tasks]
Name: "firewall"; Description: "{cm:FirewallTask}"; Check: IsFullRole

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
Filename: "http://localhost:{code:GetPort}/"; Description: "{cm:OpenGui}"; Flags: postinstall shellexec nowait skipifsilent; Check: IsFullRole
Filename: "{sys}\notepad.exe"; Parameters: """{code:GetPasswordFile}"""; Description: "{cm:ShowPassword}"; Flags: postinstall nowait skipifsilent unchecked; Check: ShowPasswordOption

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\service.ps1"" -Action Uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
var
  RolePage: TInputOptionWizardPage;
  ConnPage: TInputQueryWizardPage;
  PortPage: TInputQueryWizardPage;
  PreviousPort: String;
  PreviousRole: String;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\FileAccessMonitor');
end;

function AgentConfigFile(): String;
begin
  Result := DataDir() + '\agent.json';
end;

// Called by [Tasks] checks, possibly before the wizard pages exist
function IsAgentRole(): Boolean;
begin
  if RolePage <> nil then
    Result := RolePage.SelectedValueIndex = 1
  else
    Result := PreviousRole = 'agent';
end;

function IsFullRole(): Boolean;
begin
  Result := not IsAgentRole();
end;

function GetPasswordFile(Param: String): String;
begin
  Result := DataDir() + '\initial-admin-password.txt';
end;

function PasswordFileExists(): Boolean;
begin
  Result := FileExists(GetPasswordFile(''));
end;

function ShowPasswordOption(): Boolean;
begin
  Result := IsFullRole() and PasswordFileExists();
end;

function GetPort(Param: String): String;
begin
  Result := Trim(PortPage.Values[0]);
end;

function GetConnection(): String;
begin
  Result := Trim(ConnPage.Values[0]);
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

// Runs "FileAccessMonitor.exe enroll <connection string>"; on failure Output has its message
function Enroll(var Output: String): Boolean;
var
  OutFile: String;
  Content: AnsiString;
  ResultCode: Integer;
begin
  OutFile := ExpandConstant('{tmp}\enroll.txt');
  if not Exec(ExpandConstant('{cmd}'),
              '/c ""' + ExpandConstant('{app}\{#AppExe}') + '" enroll ' + GetConnection() + ' > "' + OutFile + '" 2>&1"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Output := '';
  if LoadStringFromFile(OutFile, Content) then
    Output := String(Content);
  Result := ResultCode = 0;
end;

procedure InitializeWizard();
begin
  PreviousPort := GetPreviousData('Port', '8080');
  PreviousRole := GetPreviousData('Role', '');
  if PreviousRole = '' then
  begin
    if FileExists(AgentConfigFile()) then
      PreviousRole := 'agent'
    else
      PreviousRole := 'full';
  end;
  // Silent installs can pass /ROLE=agent
  PreviousRole := Lowercase(ExpandConstant('{param:ROLE|' + PreviousRole + '}'));

  RolePage := CreateInputOptionPage(wpSelectDir, CustomMessage('RoleCaption'), CustomMessage('RoleDescription'), '', True, False);
  RolePage.Add(CustomMessage('RoleFull'));
  RolePage.Add(CustomMessage('RoleAgent'));
  if PreviousRole = 'agent' then
    RolePage.SelectedValueIndex := 1
  else
    RolePage.SelectedValueIndex := 0;

  ConnPage := CreateInputQueryPage(RolePage.ID, CustomMessage('ConnCaption'), CustomMessage('ConnDescription'), '');
  ConnPage.Add(CustomMessage('ConnPrompt'), False);
  // Silent installs can pass /CONNECTION=FAM1.xxxx
  ConnPage.Values[0] := ExpandConstant('{param:CONNECTION|}');

  PortPage := CreateInputQueryPage(ConnPage.ID, CustomMessage('PortCaption'), CustomMessage('PortDescription'), '');
  PortPage.Add(CustomMessage('PortPrompt'), False);
  // Silent installs can pass /PORT=nnnn
  PortPage.Values[0] := ExpandConstant('{param:PORT|' + PreviousPort + '}');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = ConnPage.ID then
    Result := not IsAgentRole()
  else if PageID = PortPage.ID then
    Result := IsAgentRole();
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'Port', GetPort(''));
  if IsAgentRole() then
    SetPreviousData(PreviousDataKey, 'Role', 'agent')
  else
    SetPreviousData(PreviousDataKey, 'Role', 'full');
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
  end
  else if CurPageID = ConnPage.ID then
  begin
    // Upgrading an agent that is already registered: the connection string can stay empty
    if not ((GetConnection() = '') and FileExists(AgentConfigFile())) and (Pos('FAM1.', GetConnection()) <> 1) then
    begin
      MsgBox(CustomMessage('ConnInvalid'), mbError, MB_OK);
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

procedure InstallAgent();
var
  Output: String;
  Code: Integer;
begin
  if GetConnection() <> '' then
  begin
    WizardForm.StatusLabel.Caption := CustomMessage('Enrolling');
    if not Enroll(Output) then
    begin
      // Without agent.json the service would start as a standalone install, so leave it off
      MsgBox(FmtMessage(CustomMessage('EnrollFailed'), [Output]), mbError, MB_OK);
      Exit;
    end;
  end;
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingService');
  Code := RunServiceScript('-Action Install');
  if Code <> 0 then
    MsgBox(FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(Code)]), mbError, MB_OK);
end;

procedure InstallFull();
var
  Args: String;
  Code: Integer;
begin
  // Switching an agent back to a standalone install
  if FileExists(AgentConfigFile()) then
    DeleteFile(AgentConfigFile());
  WritePortSetting();
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingService');
  Args := '-Action Install';
  if WizardIsTaskSelected('firewall') then
    Args := Args + ' -Firewall';
  Code := RunServiceScript(Args);
  if Code <> 0 then
    MsgBox(FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(Code)]), mbError, MB_OK)
  else
    Sleep(3000);  // give the service time to create the initial admin password file
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if IsAgentRole() then
      InstallAgent()
    else
      InstallFull();
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    if IsAgentRole() then
      WizardForm.FinishedLabel.Caption := FmtMessage(CustomMessage('AgentFinishInfo'), [ExpandConstant('{app}')])
    else
      WizardForm.FinishedLabel.Caption := FmtMessage(CustomMessage('FinishInfo'), [GetPasswordFile('')]);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and DirExists(DataDir()) and not UninstallSilent() then
    MsgBox(FmtMessage(CustomMessage('UninstallKeptData'), [DataDir()]), mbInformation, MB_OK);
end;
