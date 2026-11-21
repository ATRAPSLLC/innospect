; Pre-5 sample, in the script dialect every compiler from 1.3 on accepts:
; no Compression, no Tasks: or Components: parameters (1.3 rejects them; it
; skips the [Types], [Components] and [Tasks] sections it does not know).
; Compiled by each Inno Setup 1.3 to 4.2 in versions.txt, one per setup
; data marker. Output: `legacy.exe`. CRLF line endings: the 1.x to 4.x
; compilers find no [Setup] section in an LF-only script.

[Setup]
AppName=Inno Test (legacy)
AppVerName=Inno Test (legacy) 1.0.0
AppPublisher=BinFlip
AppPublisherURL=https://example.invalid/
DefaultDirName={pf}\InnoTestLegacy
DefaultGroupName=Inno Test Legacy
OutputDir=.
OutputBaseFilename=legacy

[Types]
Name: "full"; Description: "Full installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "main"; Description: "Main files"; Types: full custom; Flags: fixed
Name: "extra"; Description: "Extra files"; Types: full

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"

[Dirs]
Name: "{app}\data"

[Files]
Source: "payload.txt"; DestDir: "{app}"

[Icons]
Name: "{group}\Payload"; Filename: "{app}\payload.txt"

[INI]
Filename: "{app}\legacy.ini"; Section: "Main"; Key: "Version"; String: "1.0.0"

[Registry]
Root: HKCU; Subkey: "Software\InnoTestLegacy"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey

[InstallDelete]
Type: files; Name: "{app}\stale.txt"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\data"

[Run]
Filename: "{app}\payload.txt"; Flags: shellexec nowait

[UninstallRun]
Filename: "{sys}\cmd.exe"; Parameters: "/c echo Inno test uninstall"
