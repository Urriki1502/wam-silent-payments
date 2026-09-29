#!/bin/sh
set -eu
: "${WAMD:?Set WAMD to the verified absolute WAM daemon path}"
: "${WAMD_SHA256:?Set WAMD_SHA256 to the verified executable digest}"
python -m devtools.real_node --wamd "$WAMD" --sha256 "$WAMD_SHA256"
python -m devtools.interop --wamd "$WAMD" --sha256 "$WAMD_SHA256"
python -m devtools.regtest --wamd "$WAMD" --sha256 "$WAMD_SHA256"
