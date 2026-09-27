#!/bin/bash
# Builds the Inno Setup fixtures on Linux, under Wine, with no Windows host.
#
# The official compilers `versions.txt` lists run in the image `Dockerfile`
# describes, with this directory bind-mounted so a script edit needs no image
# rebuild.
#
# Usage:
#
#   ./build-wine.sh --all                    # the whole matrix in versions.txt
#   ./build-wine.sh <slug> <script> [...]    # e.g. ./build-wine.sh 6_4_3 plain code
#
# `<slug>` is a row of `versions.txt`; `<script>` is an `.iss` here without its
# extension. Each output lands where the tests look for it:
#
#   plain.iss           -> ../plain/plain-tool<slug>.exe
#   encrypted.iss       -> ../encrypted/enc-files-tool<slug>.exe
#   encrypted-full.iss  -> ../encrypted/enc-full-tool<slug>.exe
#   <name>.iss          -> ../<name>/<name>-tool<slug>.exe
#
# and a second build of the same script with `--alt` as the first argument
# lands at the same name with `-alt` appended - the nondeterminism check.

set -euo pipefail

cd "$(dirname "$0")"

IMAGE="inno-fixtures:wine"

# The image is rebuilt when anything it is built from is newer than it, so a
# version added to the matrix is picked up without a manual step.
ensure_image() {
    local created newest
    created="$(docker image inspect -f '{{.Created}}' "$IMAGE" 2>/dev/null || true)"
    newest="$(stat -c %Y Dockerfile versions.txt install-inno.sh | sort -n | tail -1)"
    if [ -z "$created" ] || [ "$(date -d "$created" +%s)" -lt "$newest" ]; then
        docker build -t "$IMAGE" .
    fi
}

destination() {
    local slug="$1" script="$2" suffix="$3"
    case "$script" in
        plain)          echo "../plain/plain-tool${slug}${suffix}.exe" ;;
        encrypted)      echo "../encrypted/enc-files-tool${slug}${suffix}.exe" ;;
        encrypted-full) echo "../encrypted/enc-full-tool${slug}${suffix}.exe" ;;
        *)              echo "../${script}/${script}-tool${slug}${suffix}.exe" ;;
    esac
}

# Compiles one script with one compiler and files the output.
build() {
    local slug="$1" script="$2" suffix="$3" base out
    [ -f "${script}.iss" ] || { echo "no ${script}.iss here" >&2; exit 1; }
    base="$(sed -n 's/^OutputBaseFilename=//p' "${script}.iss" | tr -d '\r')"
    [ -n "$base" ] || { echo "${script}.iss names no OutputBaseFilename" >&2; exit 1; }

    echo "[${slug}] ${script}${suffix}"
    docker run --rm -v "$PWD:/work" -w /work "$IMAGE" bash -c "
        set -e
        test -f \"\$WINEPREFIX/drive_c/inno/${slug}/ISCC.exe\" \
            || { echo 'no compiler ${slug} in the image; add it to versions.txt' >&2; exit 1; }
        xvfb-run -a wine 'C:\\inno\\${slug}\\ISCC.exe' /Q 'Z:\\work\\${script}.iss'
        wineserver -w
        chown $(id -u):$(id -g) '${base}.exe'
    " 2> >(grep -v XDG_RUNTIME_DIR >&2)

    out="$(destination "$slug" "$script" "$suffix")"
    mkdir -p "$(dirname "$out")"
    mv "${base}.exe" "$out"
    echo "[${slug}] -> ${out}"
}

ensure_image

if [ "${1:-}" = "--all" ]; then
    grep -v '^\s*\(#\|$\)' versions.txt | while read -r slug _ scripts; do
        IFS=, read -ra list <<< "$scripts"
        for script in "${list[@]}"; do
            [ "$script" = alt ] || build "$slug" "$script" ""
        done
        if [[ ",${scripts}," == *",alt,"* ]]; then
            for script in "${list[@]}"; do
                [ "$script" = alt ] || build "$slug" "$script" "-alt"
            done
        fi
    done
    exit 0
fi

suffix=""
if [ "${1:-}" = "--alt" ]; then suffix="-alt"; shift; fi
slug="${1:?usage: build-wine.sh --all | [--alt] <slug> <script> ...}"
shift
[ "$#" -gt 0 ] || { echo "usage: build-wine.sh [--alt] <slug> <script> ..." >&2; exit 2; }
for script in "$@"; do
    build "$slug" "$script" "$suffix"
done
