#!/bin/bash
# Installs every Inno Setup compiler `versions.txt` lists into the Wine
# prefix, one directory each.
#
# Usage (inside the image, see Dockerfile):  install-inno.sh versions.txt
#
# Each installer runs silently to `C:\inno\<slug>`, is checked for
# `ISCC.exe` before the next one runs, and gets the encryption add-on beside
# it. Its uninstall registration is removed afterwards: every Inno Setup of
# one major version shares an AppId, so a second install would otherwise find
# the first and reuse its directory.
#
# Under `xvfb-run` because Setup creates windows even when silent, and Wine
# has no display driver to create them on without one.

set -euo pipefail

# The encryption add-on the pre-6.4 compilers need to encrypt at all ("Cannot
# use encryption because ISCrypt.dll is missing"). One DLL serves every
# version; 6.4 and later encrypt natively and ignore it. Pinned by hash, since
# the URL names no version.
ISCRYPT_URL="https://jrsoftware.org/download.php/iscrypt.dll"
ISCRYPT_SHA256="2f6294f9aa09f59a574b5dcd33be54e16b39377984f3d5658cda44950fa0f8fc"
curl -fsSL -o /tmp/ISCrypt.dll "${ISCRYPT_URL}"
echo "${ISCRYPT_SHA256}  /tmp/ISCrypt.dll" | sha256sum -c -

grep -v '^\s*\(#\|$\)' "$1" | while read -r slug url _; do
    installer="/tmp/inno-${slug}.exe"
    echo "[inno ${slug}] ${url}"
    curl -fsSL -o "${installer}" "${url}"

    xvfb-run -a wine "${installer}" /VERYSILENT /SUPPRESSMSGBOXES /SP- /NOICONS \
        "/DIR=C:\\inno\\${slug}"
    wineserver -w

    iscc="${WINEPREFIX}/drive_c/inno/${slug}/ISCC.exe"
    test -f "${iscc}" || { echo "[inno ${slug}] no ISCC.exe at ${iscc}" >&2; exit 1; }
    cp /tmp/ISCrypt.dll "$(dirname "${iscc}")/ISCrypt.dll"

    for hive in 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall' \
                'HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; do
        wine reg delete "${hive}\\Inno Setup ${slug%%_*}_is1" /f >/dev/null 2>&1 || true
    done
    wineserver -w
    rm -f "${installer}"
    echo "[inno ${slug}] installed"
done
