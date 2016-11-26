#! /bin/bash
set -e

IFS=':' read -ra ADDR <<< "$1"
shift
HOST="${ADDR[0]}"
PORT="${ADDR[1]}"

/picotls/cli -s /session -e "$@" $HOST $PORT < /httpreq.txt
/picotls/cli -s /session -e "$@" $HOST $PORT < /httpreq.txt
