; Inno Setup: bộ cài afing cho Windows.
;   iscc /DAppVersion=1.0.0 packaging\afing.iss      (kết quả: dist\afing-setup.exe)
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F0C1C6E-6E0B-4B62-9B5E-AF1A6F1A0001}
AppName=afing
AppVersion={#AppVersion}
AppPublisher=afing
DefaultDirName={autopf}\afing
DefaultGroupName=afing
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; afing.exe la ung dung 64-bit: cai vao Program Files (khong phai Program Files (x86))
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=afing-setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\afing.exe
CloseApplications=no

[Files]
Source: "..\dist\afing.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\afing-tray.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\afing dashboard"; Filename: "{app}\afing.exe"
Name: "{group}\Uninstall afing"; Filename: "{uninstallexe}"

[Run]
; Dang ky tu chay khi Windows khoi dong (kem bieu tuong khay he thong) va chay ngay.
Filename: "{app}\afing.exe"; Parameters: "install-autostart"; Flags: runhidden; StatusMsg: "Starting afing..."
Filename: "{app}\afing.exe"; Description: "Open the afing dashboard"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\afing.exe"; Parameters: "uninstall-autostart"; Flags: runhidden; RunOnceId: "afingAutostart"

[Code]
// Nang cap: dung ban dang chay truoc khi chep de file exe.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  if FileExists(ExpandConstant('{app}\afing.exe')) then
    Exec(ExpandConstant('{app}\afing.exe'), 'uninstall-autostart', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
