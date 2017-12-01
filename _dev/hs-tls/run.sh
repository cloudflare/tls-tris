#! /bin/bash
set -e

IFS=':' read -ra ADDR <<< "$1"
shift
HOST="${ADDR[0]}"
PORT="${ADDR[1]}"

# Documentation:
# https://github.com/vincenthz/hs-tls/issues/167#issuecomment-261823166
# "-g x25519" is used since HRR is not supported yet by tris.

exec stack exec tls-simpleclient -- --no-valid --http1.1 \
    --session -Z /httpreq.txt -g x25519 "$HOST" "$PORT"
