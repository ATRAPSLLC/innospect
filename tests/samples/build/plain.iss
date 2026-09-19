; Plaintext sample. Compiles under any Inno Setup ≥ 5.0 (no
; modern-only directives). Output: `plain.exe`.
;
; Build: ISCC.exe plain.iss
; SCP back as `plain-tool<X_Y_Z>.exe` once landed locally.

[Setup]
AppName=Inno Test (plain)
AppVersion=1.0.0
; AppVerName is required by pre-5.3 ISCC; modern versions accept it
; as a deprecated alias for the AppName + AppVersion pair.
AppVerName=Inno Test (plain) 1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestPlain
OutputDir=.
OutputBaseFilename=plain
Compression=lzma
SolidCompression=yes

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

; See encrypted.iss for the rationale - every rebuild needs at least one
; [Run]/[UninstallRun] entry to exercise `RunEntry::read` (Run.OnLog,
; Run.Bitness cutoffs).
[Run]
Filename: "{cmd}"; Parameters: "/c echo Inno test run"; Flags: runhidden

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c echo Inno test uninstall"; Flags: runhidden
