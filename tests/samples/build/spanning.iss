; Disk spanning: the payload in setup-N.bin slices beside the installer.
; Compiles under Inno Setup >= 4.0 (`DiskSliceSize`, `SlicesPerDisk`); 1.x
; and 2.x take `spanning-legacy.iss`. Output: `spanning.exe` and its slices.
;
; The installer itself must fit in the first slice (over 2 MiB from 6.x), so
; slices are 2.5 MiB, and `spanning\random.bin`, 600 KiB that does not
; compress, is stored five times, unmerged and one chunk each, so that one
; chunk runs from the first slice into the second. Twelve slices to a disk
; name them `-1a`, `-1b`, ...

[Setup]
AppName=Inno Test (spanning)
AppVerName=Inno Test (spanning) 1.0.0
DefaultDirName={pf}\InnoTestSpanning
OutputDir=.
OutputBaseFilename=spanning
DiskSpanning=yes
DiskSliceSize=2621440
DontMergeDuplicateFiles=yes
SlicesPerDisk=12

[Files]
Source: "spanning\random.bin"; DestDir: "{app}"; DestName: "random1.bin"
Source: "spanning\random.bin"; DestDir: "{app}"; DestName: "random2.bin"
Source: "spanning\random.bin"; DestDir: "{app}"; DestName: "random3.bin"
Source: "spanning\random.bin"; DestDir: "{app}"; DestName: "random4.bin"
Source: "spanning\random.bin"; DestDir: "{app}"; DestName: "random5.bin"
Source: "payload.txt"; DestDir: "{app}"
