; Feature-rich sample: every record stream a real-world installer carries,
; built from a script we own so each value a test asserts is stated here.
; Compiles under Inno Setup >= 6.1. Output: `full.exe`; land it locally as
; `full-tool<slug>.exe` (`build-wine.sh` does).
;
; It replaces the third-party installers the suite used to fetch, and covers
; what they did: many languages (including non-Latin codepages), custom
; messages, a license, tasks, files in solid and per-file chunks and one
; stored uncompressed, icons resolving to an installed file, registry entries
; under HKCR, HKCU, HKLM and HKA with every value type and every operation
; Setup performs (write, write if missing, create the key, delete a value or
; a key, replace either, record for the uninstaller only), a post-install
; run entry, and a compiled [Code] script importing the Inno API.
;
; The payload lives in `full/`, and its contents are fixed: `app.exe` is 65536
; bytes starting `MZ`, `license.txt` 1852 bytes, `readme.txt` 21 bytes, `stored.txt`
; 21 bytes (stored without compression), and `docs/doc1..5.txt`.

[Setup]
AppId=InnoTestFull
AppName=Inno Test (full)
AppVersion=2.3.4.5
AppVerName=Inno Test (full) 2.3.4.5
AppPublisher=BinFlip
AppPublisherURL=https://example.invalid/
DefaultDirName={autopf}\InnoTestFull
DefaultGroupName=Inno Test Full
LicenseFile=full\license.txt
ChangesAssociations=yes
; 6.3 introduced the `x64compatible` identifier and stores the setting as a
; string; earlier versions take `x64` and store a packed set.
#if Ver >= 0x06030000
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
#endif
OutputDir=.
OutputBaseFilename=full
; Each format is built with the layout of the installer it stands in for:
; 6.4 with LZMA2 in one solid chunk (files at non-zero offsets inside it), 6.1
; with LZMA1 and one chunk per file (the executable through the x86 filter).
#if Ver >= 0x06040000
Compression=lzma2
SolidCompression=yes
#else
Compression=lzma
SolidCompression=no
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"

[CustomMessages]
english.Greeting=Hello from the full fixture
german.Greeting=Hallo aus dem vollen Beispiel
LaunchApp=Launch the test application

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunch"; Description: "Create a Quick Launch icon"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "associate"; Description: "Associate .innotest files"; GroupDescription: "File associations"
Name: "startup"; Description: "Start with Windows"; Flags: unchecked
Name: "docs"; Description: "Install the documents"

[Files]
Source: "full\app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "full\license.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "full\readme.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "full\docs\*.txt"; DestDir: "{app}\docs"; Tasks: docs; Flags: ignoreversion
; Stored as is, in a chunk of its own: the uncompressed-chunk path.
Source: "full\stored.txt"; DestDir: "{app}"; Flags: ignoreversion nocompression

[Icons]
Name: "{group}\Inno Test Full"; Filename: "{app}\app.exe"
Name: "{group}\Readme"; Filename: "{app}\readme.txt"
Name: "{group}\{cm:UninstallProgram,Inno Test Full}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Inno Test Full"; Filename: "{app}\app.exe"; Tasks: desktopicon

[Registry]
Root: HKCR; Subkey: ".innotest"; ValueType: string; ValueName: ""; ValueData: "InnoTestFile"; Flags: uninsdeletevalue; Tasks: associate
Root: HKCR; Subkey: "InnoTestFile"; ValueType: string; ValueName: ""; ValueData: "Inno test file"; Flags: uninsdeletekey; Tasks: associate
Root: HKCR; Subkey: "InnoTestFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\app.exe,0"; Tasks: associate
Root: HKCR; Subkey: "InnoTestFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\app.exe"" ""%1"""; Tasks: associate
Root: HKCU; Subkey: "Software\InnoTestFull"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\InnoTestFull"; ValueType: dword; ValueName: "Runs"; ValueData: "0"
Root: HKLM; Subkey: "Software\InnoTestFull"; ValueType: string; ValueName: "Version"; ValueData: "2.3.4.5"; Flags: uninsdeletekey
; The other value types, and HKA (HKLM or HKCU by install mode).
Root: HKA; Subkey: "Software\InnoTestFull"; ValueType: expandsz; ValueName: "Temp"; ValueData: "%TEMP%\InnoTestFull"
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: binary; ValueName: "Blob"; ValueData: "01 02 ff"
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: multisz; ValueName: "Lines"; ValueData: "one{break}two"
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: qword; ValueName: "Big"; ValueData: "$123456789"
; One entry for each thing Setup can do with an entry (`RegistryOpKind`).
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: string; ValueName: "IfMissing"; ValueData: "first"; Flags: createvalueifdoesntexist
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds\Empty"; ValueType: none
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: none; ValueName: "Stale"; Flags: deletevalue
Root: HKCU; Subkey: "Software\InnoTestFull\Old"; ValueType: none; Flags: deletekey
Root: HKCU; Subkey: "Software\InnoTestFull\Kinds"; ValueType: dword; ValueName: "Swap"; ValueData: "7"; Flags: deletevalue
Root: HKCU; Subkey: "Software\InnoTestFull\Fresh"; ValueType: string; ValueName: "Value"; ValueData: "new"; Flags: deletekey
Root: HKCU; Subkey: "Software\InnoTestFull\Mark"; ValueType: none; Flags: dontcreatekey uninsdeletekey
; Bitness (`HKLM64`): a flag before 7.0.0.3, a byte of its own from it.
Root: HKLM64; Subkey: "Software\InnoTestFull"; ValueType: string; ValueName: "Bits"; ValueData: "64"

[Run]
Filename: "{app}\app.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent 32bit

[Code]
{ An Inno API import, so the compiled script names a known host function. }
function InitializeSetup: Boolean;
var
  Previous: String;
begin
  if RegQueryStringValue(HKCU, 'Software\InnoTestFull', 'InstallDir', Previous) then
    Log('previous install at ' + Previous);
  Result := True;
end;
