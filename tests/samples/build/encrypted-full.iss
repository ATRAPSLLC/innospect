; euFull sample - `Encryption=full` directive available 6.5.0+.
; Produces an installer where the setup-0 stream itself is
; XChaCha20-encrypted (sccCompressedBlocks1/2 contexts), in
; addition to the per-chunk encryption.
;
; **Skip on Inno Setup < 6.5** - the directive doesn't exist
; there and ISCC will reject the script.
;
; Build: ISCC.exe encrypted-full.iss
; SCP back as `enc-full-tool<X_Y_Z>.exe`.

[Setup]
AppName=Inno Test (euFull)
AppVersion=1.0.0
; AppVerName is only relevant pre-5.3 (where it's required); kept here
; for consistency with plain.iss / encrypted.iss. encrypted-full.iss
; itself is 6.5+ only since `Encryption=full` doesn't exist earlier.
AppVerName=Inno Test (euFull) 1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestEncFull
OutputDir=.
OutputBaseFilename=encrypted-full
Compression=lzma2
SolidCompression=yes
Password=test123
Encryption=full

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

; See encrypted.iss for the rationale - every rebuild needs at least one
; [Run]/[UninstallRun] entry to exercise `RunEntry::read` (Run.OnLog,
; Run.Bitness cutoffs).
[Run]
Filename: "{cmd}"; Parameters: "/c echo Inno test run"; Flags: runhidden

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c echo Inno test uninstall"; Flags: runhidden
