#!/bin/bash
# Installs every Inno Setup compiler `versions.txt` lists into the Wine
# prefix, one directory each.
#
# Usage (inside the image, see Dockerfile):  install-inno.sh versions.txt
#
# Each installer from 5.0 on runs silently to `C:\inno\<slug>`, is checked
# for `ISCC.exe` before the next one runs, and gets the encryption add-on
# beside it. Its uninstall registration is removed afterwards: every Inno
# Setup of one major version shares an AppId, so a second install would
# otherwise find the first and reuse its directory.
#
# A 1.x to 4.x package is unpacked with innoextract instead: nothing of it
# needs installing beyond its files, and 1.3.26's Setup never returns under
# Wine. 1.3.26 ships no command-line compiler, only `Compil32.exe /cc`, which
# hangs the same way, so it gets 2.0.19's `ISCC.exe`: a front end that loads
# the `ISCmplr.dll` beside it through an interface (`CompInt.pas`) the two
# releases declare identically, so the compiling is still 1.3.26's own.
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

ISCC_FRONT_END_URL="https://files.jrsoftware.org/is/2/isetup-2.0.19.exe"

grep -v '^\s*\(#\|$\)' "$1" | while read -r slug url _; do
    installer="/tmp/inno-${slug}.exe"
    echo "[inno ${slug}] ${url}"
    curl -fsSL -o "${installer}" "${url}"

    dir="${WINEPREFIX}/drive_c/inno/${slug}"
    case "${slug}" in
        [1-4]_*)
            innoextract --silent --extract --output-dir "/tmp/unpacked-${slug}" "${installer}"
            mkdir -p "${dir}"
            cp -r "/tmp/unpacked-${slug}/app/." "${dir}/"
            rm -rf "/tmp/unpacked-${slug}"
            if [ ! -f "${dir}/ISCC.exe" ]; then
                curl -fsSL -o /tmp/iscc-front-end.exe "${ISCC_FRONT_END_URL}"
                innoextract --silent --extract --include app/ISCC.exe \
                    --output-dir /tmp/iscc-front-end /tmp/iscc-front-end.exe
                cp /tmp/iscc-front-end/app/ISCC.exe "${dir}/ISCC.exe"
                rm -rf /tmp/iscc-front-end /tmp/iscc-front-end.exe
            fi
            ;;
        *)
            xvfb-run -a wine "${installer}" /VERYSILENT /SUPPRESSMSGBOXES /SP- /NOICONS \
                "/DIR=C:\\inno\\${slug}"
            wineserver -w
            ;;
    esac

    iscc="${dir}/ISCC.exe"
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
