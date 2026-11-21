; Wizard images and the 7-Zip DLL: what setup-0 carries after the records
; from 6.6 on. Compiles under Inno Setup >= 6.6.1. Output: `modern.exe`.
;
; `WizardStyle=modern dynamic` makes the compiler store dark-mode images
; beside the light ones: its built-in dark large image, which differs from
; the light one, and for the small image the same file as for light mode,
; which it stores as "same as light" (a count of -1). From 6.7 a back image,
; `modern\back.png`, and `ArchiveExtraction=full`, which stores the
; compiler's `is7z.dll`.

[Setup]
AppName=Inno Test (modern)
AppVersion=1.0.0
AppPublisher=BinFlip
DefaultDirName={tmp}\InnoTestModern
OutputDir=.
OutputBaseFilename=modern
WizardStyle=modern dynamic
WizardSmallImageFile=modern\small.png
WizardSmallImageFileDynamicDark=modern\small.png
#if Ver >= 0x06070000
WizardBackImageFile=modern\back.png
#endif
ArchiveExtraction=full

[Files]
Source: "payload.txt"; DestDir: "{app}"; Flags: ignoreversion
