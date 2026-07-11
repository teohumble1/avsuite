; TeoAvSuite Installer Script
; Build with: Inno Setup (https://jrsoftware.org/isdl.php)
; Command: "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" TeoAvSuite.iss

#define RelDir "..\build\release\src\dashboard_ui\Release"

[Setup]
AppName=TeoAvSuite
AppVersion=1.0.3
AppPublisher=TeoHumble Security
AppPublisherURL=https://github.com/teohumble1/avsuite
AppSupportURL=https://github.com/teohumble1/avsuite/issues
AppUpdatesURL=https://github.com/teohumble1/avsuite/releases
DefaultDirName={autopf}\TeoAvSuite
DefaultGroupName=TeoAvSuite
AllowNoIcons=yes
OutputDir=.\Output
OutputBaseFilename=TeoAvSuite-Setup-v1.0.3
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ShowLanguageDialog=auto
WizardStyle=modern
LicenseFile=..\LICENSE
MinVersion=10.0
; Branding: amber shield icon on the setup exe + dark wizard art
SetupIconFile=..\src\dashboard_ui\resources\app.ico
WizardImageFile=wizard-large.bmp
WizardSmallImageFile=wizard-small.bmp
UninstallDisplayIcon={app}\avdashboard.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Start TeoAvSuite on system startup"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
Source: "{#RelDir}\avdashboard.exe"; DestDir: "{app}"; Flags: ignoreversion

; All DLL dependencies (Qt, ML/AI, crypto, etc.)
Source: "{#RelDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion

; Qt platform plugins
Source: "{#RelDir}\platforms\*"; DestDir: "{app}\platforms"; Flags: ignoreversion recursesubdirs createallsubdirs

; Runtime window/taskbar icon (loaded by main.cpp next to the exe)
Source: "{#RelDir}\app_icon.png"; DestDir: "{app}"; Flags: ignoreversion

; YARA rules
Source: "{#RelDir}\yara_rules\*"; DestDir: "{app}\yara_rules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Config file -- ship a sanitized default (empty API keys, portable paths), NOT
; the developer's build-tree avsuite.json which contains a real VirusTotal key
; and absolute D:\Dev paths. onlyifdoesntexist preserves a user's own settings
; on upgrade.
Source: "avsuite.default.json"; DestDir: "{app}"; DestName: "avsuite.json"; Flags: onlyifdoesntexist

; Documentation
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.txt"; Flags: isreadme
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"

[Icons]
Name: "{group}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"
Name: "{group}\{cm:UninstallProgram,TeoAvSuite}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; Tasks: desktopicon
Name: "{commonstartup}\TeoAvSuite"; Filename: "{app}\avdashboard.exe"; Tasks: startupicon

[Run]
Filename: "{app}\avdashboard.exe"; Description: "{cm:LaunchProgram,TeoAvSuite}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\yara_rules"
Type: filesandordirs; Name: "{app}\platforms"

[Registry]
Root: HKCU; Subkey: "Software\TeoAvSuite"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: createvalueifdoesntexist
Root: HKCU; Subkey: "Software\TeoAvSuite"; ValueType: string; ValueName: "Version"; ValueData: "1.0.3"; Flags: createvalueifdoesntexist

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    MsgBox('TeoAvSuite installed successfully!' + #13 + #13 +
           'Features:' + #13 +
           '- Realtime malware detection' + #13 +
           '- YARA rule scanning' + #13 +
           '- Quarantine management with Select All' + #13 +
           '- AI-powered threat analysis (Qwen2.5-7B)' + #13 +
           '- ETW monitoring' + #13 +
           '' + #13 +
           'Visit: https://github.com/teohumble1/avsuite', mbInformation, MB_OK);
  end;
end;
