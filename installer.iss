; TeoAvSuite - Inno Setup installer script
; Compile with: Inno Setup 6 (https://jrsoftware.org/isinfo.php)
; Run package.ps1 first to create the dist\ folder.

#define AppName      "TeoAvSuite"
#define AppVersion   "1.0.0"
#define AppPublisher "TeoAvSuite"
#define AppURL       ""
#define AppExe       "avdashboard.exe"
#define AppAmsi      "avamsi.dll"
#define DistDir      "dist"

[Setup]
AppId={{B3A7C2D1-1F4E-4A9B-8C3D-6E2F0A1B5C4D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=no
OutputDir=output
OutputBaseFilename=TeoAvSuite-Setup-v{#AppVersion}
SetupIconFile=
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
DisableProgramGroupPage=no
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
; Create a logs dir so the app can write to it without UAC issues
; (app itself writes to %AppData%\TeoAvSuite at runtime)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Tạo shortcut trên Desktop"; GroupDescription: "Shortcut:"

[Files]
; Main executable
Source: "{#DistDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

; All DLLs (Qt6, ggml, llama, sqlite3, spdlog, OpenSSL, etc.)
Source: "{#DistDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion

; Qt platform plugin
Source: "{#DistDir}\platforms\qwindows.dll"; DestDir: "{app}\platforms"; Flags: ignoreversion

; YARA detection rules
Source: "{#DistDir}\yara_rules\*"; DestDir: "{app}\yara_rules"; Flags: ignoreversion recursesubdirs

; AMSI provider (optional - only if built)
Source: "{#DistDir}\{#AppAmsi}"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
; Pre-create writable dirs (user data goes here via the app, not Program Files)
Name: "{userappdata}\TeoAvSuite"
Name: "{userappdata}\TeoAvSuite\quarantine"
Name: "{userappdata}\TeoAvSuite\logs"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Gỡ cài đặt {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; AMSI provider registration — allows TeoAvSuite to intercept script execution
; COM CLSID for avamsi.dll
Root: HKLM; Subkey: "SOFTWARE\Classes\CLSID\{{A5F6A8B2-3C1D-4E7F-9B0A-2D4E6F8A1C3B}"; ValueType: string; ValueName: ""; ValueData: "TeoAvSuite AMSI Provider"; Flags: uninsdeletekey; Check: AmsiDllExists
Root: HKLM; Subkey: "SOFTWARE\Classes\CLSID\{{A5F6A8B2-3C1D-4E7F-9B0A-2D4E6F8A1C3B}\InprocServer32"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppAmsi}"; Flags: uninsdeletekey; Check: AmsiDllExists
Root: HKLM; Subkey: "SOFTWARE\Classes\CLSID\{{A5F6A8B2-3C1D-4E7F-9B0A-2D4E6F8A1C3B}\InprocServer32"; ValueType: string; ValueName: "ThreadingModel"; ValueData: "Both"; Flags: uninsdeletekey; Check: AmsiDllExists
Root: HKLM; Subkey: "SOFTWARE\Microsoft\AMSI\Providers\{{A5F6A8B2-3C1D-4E7F-9B0A-2D4E6F8A1C3B}"; ValueType: string; ValueName: ""; ValueData: "TeoAvSuite AMSI Provider"; Flags: uninsdeletekey; Check: AmsiDllExists

[Code]
function AmsiDllExists: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\{#AppAmsi}'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    // Write a default config pointing to the install dir for yara_rules
    // The app will pick this up on first launch.
    // (actual config is stored in %AppData%\TeoAvSuite\avsuite.json at runtime)
  end;
end;
