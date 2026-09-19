; Encrypted sample (default mode). Pre-6.5 produces ARC4-via-
; `Password=` (ARC4-SHA1 for ≥ 5.3.9, ARC4-MD5 for older).
; 6.5+ produces XChaCha20 / euFiles by default. Output:
; `encrypted.exe`.
;
; Build: ISCC.exe encrypted.iss
; SCP back as `enc-files-tool<X_Y_Z>.exe` once landed locally.

[Setup]
AppName=Inno Test (encrypted)
AppVersion=1.0.0
; AppVerName is required by pre-5.3 ISCC; modern versions accept it
; as a deprecated alias for the AppName + AppVersion pair.
AppVerName=Inno Test (encrypted) 1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestEnc
OutputDir=.
OutputBaseFilename=encrypted
Compression=lzma
SolidCompression=yes
Password=test123
; 6.5+ defaults to Encryption=no (password verification only). Force
; chunk encryption explicitly so the sample exercises the actual
; per-chunk decrypt path. Pre-6.5 ISCC accepts `yes` and produces the
; same euFiles equivalent (ARC4 chunks via the legacy code path).
Encryption=yes

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion

; Exercise `RunEntry::read` on the wire. The fields are format-affecting
; per version (`Run.OnLog` added at SetupBinVersion 7.0.0.1, `Run.Bitness`
; cutoff change) - having any [Run]/[UninstallRun] entry forces the
; decoder to walk those bytes on every rebuilt sample.
[Run]
Filename: "{cmd}"; Parameters: "/c echo Inno test run"; Flags: runhidden

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c echo Inno test uninstall"; Flags: runhidden
