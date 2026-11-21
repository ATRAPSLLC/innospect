; Disk spanning in the 1.x / 2.x dialect (`DiskSize`; no `SlicesPerDisk`):
; see `spanning.iss`. Output: `spanning.exe` and its slices. CRLF line
; endings, which these compilers need.

[Setup]
AppName=Inno Test (spanning)
AppVerName=Inno Test (spanning) 1.0.0
DefaultDirName={pf}\InnoTestSpanning
OutputDir=.
OutputBaseFilename=spanning
DiskSpanning=yes
DiskSize=262144

[Files]
Source: "spanning\random.bin"; DestDir: "{app}"
Source: "payload.txt"; DestDir: "{app}"
