; TeoAvSuite Installer Script
; Build with: Inno Setup (https://jrsoftware.org/isdl.php)
; Command: "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" TeoAvSuite.iss

[Setup]
AppName=TeoAvSuite
AppVersion=1.0.0
AppPublisher=TeoHumble Security
AppPublisherURL=https://github.com/teohumble1/avsuite
AppSupportURL=https://github.com/teohumble1/avsuite/issues
AppUpdatesURL=https://github.com/teohumble1/avsuite/releases
DefaultDirName={pf}\TeoAvSuite
DefaultGroupName=TeoAvSuite
AllowNoIcons=yes
OutputDir=.\Output
OutputBaseFilename=TeoAvSuite-Setup-v1.0.0
SetupIconFile=..\src\dashboard_ui\resources\icon.ico
UninstallIconFile={app}\uninstall.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ShowLanguageDialog=auto
WizardStyle=modern
LicenseFile=..\LICENSE
InfoBeforeFile=..\README.md

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "vietnamese"; MessagesFile: "compiler:Languages\Vietnamese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 0,6.1
Name: "startupicon"; Description: "Start TeoAvSuite on system startup"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
Source: "..\build\release\src\dashboard_ui\Release\avdashboard.exe"; DestDir: "{app}"; Flags: ignoreversion

; Qt libraries
Source: "..\build\release\src\dashboard_ui\Release\Qt6Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\release\src\dashboard_ui\Release\Qt6Gui.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\release\src\dashboard_ui\Release\Qt6Widgets.dll"; DestDir: "{app}"; Flags: ignoreversion

; ML/AI libraries
Source: "..\build\release\src\dashboard_ui\Release\ggml*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\release\src\dashboard_ui\Release\llama.dll"; DestDir: "{app}"; Flags: ignoreversion

; Security & crypto libraries
Source: "..\build\release\src\dashboard_ui\Release\libcrypto*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\release\src\dashboard_ui\Release\sqlite3.dll"; DestDir: "{app}"; Flags: ignoreversion

; Other dependencies
Source: "..\build\release\src\dashboard_ui\Release\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\release\src\dashboard_ui\Release\platforms\qwindows*.dll"; DestDir: "{app}\platforms"; Flags: ignoreversion

; YARA rules & resources
Source: "..\build\release\src\dashboard_ui\Release\yara_rules\*"; DestDir: "{app}\yara_rules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Config files
Source: "..\build\release\src\dashboard_ui\Release\avsuite.json"; DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.txt"; Flags: isreadme
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"

[Icons]
Name: "{group}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; IconIndex: 0
Name: "{group}\{cm:UninstallProgram,TeoAvSuite}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; Tasks: desktopicon; IconIndex: 0
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; Tasks: quicklaunchicon; IconIndex: 0
Name: "{commonstartup}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; Tasks: startupicon

[Run]
Filename: "{app}\avdashboard.exe"; Description: "{cm:LaunchProgram,TeoAvSuite}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\yara_rules"
Type: filesandordirs; Name: "{app}\platforms"

[Registry]
Root: HKCU; Subkey: "Software\TeoAvSuite"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: createvalueifdoesntexist
Root: HKCU; Subkey: "Software\TeoAvSuite"; ValueType: string; ValueName: "Version"; ValueData: "1.0.0"; Flags: createvalueifdoesntexist

[Code]
function InitializeSetup: Boolean;
begin
  { Check Windows version }
  if not (IsWin10 or IsWin11) then
  begin
    MsgBox('TeoAvSuite requires Windows 10 or later.', mbCriticalError, MB_OK);
    Result := False;
  end else
    Result := True;
end;

function IsWin10: Boolean;
begin
  Result := (GetWindowsVersion and $FFFFFF) = $000A00;
end;

function IsWin11: Boolean;
begin
  Result := (GetWindowsVersion and $FFFFFF) = $000B00;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    MsgBox('TeoAvSuite installed successfully!' + #13 + #13 +
           'Features:' + #13 +
           '• Realtime malware detection' + #13 +
           '• YARA rule scanning' + #13 +
           '• Quarantine management with Select All' + #13 +
           '• AI-powered threat analysis' + #13 +
           '• ETW monitoring' + #13 +
           '' + #13 +
           'Visit: https://github.com/teohumble1/avsuite', mbInformation, MB_OK);
  end;
end;
