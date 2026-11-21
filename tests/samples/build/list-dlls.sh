#!/bin/bash
# Writes `compiler-dlls.txt`: the SHA-256 of each DLL a compiler in the image
# stores in the installers it builds (the decompressor DLLs and the 7-Zip
# library), one `<slug> <file> <sha256>` row each. The tests check a
# fixture's stored DLL against its compiler's own file.
#
# Usage: ./list-dlls.sh   (after the image is built; see build-wine.sh)

set -euo pipefail
cd "$(dirname "$0")"

docker run --rm inno-fixtures:wine bash -c '
    cd "$WINEPREFIX/drive_c/inno"
    for slug in *; do
        for dll in "$slug"/isbunzip.dll "$slug"/isunzlib.dll "$slug"/isunlzma.dll "$slug"/is7z*.dll; do
            [ -f "$dll" ] || continue
            echo "$slug $(basename "$dll" | tr "[:upper:]" "[:lower:]") $(sha256sum "$dll" | cut -d" " -f1)"
        done
    done | sort
' > compiler-dlls.txt
wc -l compiler-dlls.txt
