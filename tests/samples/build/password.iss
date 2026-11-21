; Password-only sample: `Password=` without `Encryption=`. Setup asks for the
; password, but no data is encrypted, so everything extracts without it. Pre-6.4
; stores a password hash in the header; 6.4 stores the PBKDF2 verifier there;
; 6.5+ in the encryption header, with `EncryptionUse = euNone`. Compiles under
; any Inno Setup >= 5.0. Output: `password.exe`.

[Setup]
AppName=Inno Test (password)
AppVersion=1.0.0
; AppVerName is required by pre-5.3 ISCC; modern versions accept it
; as a deprecated alias for the AppName + AppVersion pair.
AppVerName=Inno Test (password) 1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestPassword
OutputDir=.
OutputBaseFilename=password
Compression=lzma
SolidCompression=yes
Password=test123

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion
