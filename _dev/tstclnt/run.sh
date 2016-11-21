#! /bin/bash

IFS=':' read -ra ADDR <<< "$1"
shift
HOST="${ADDR[0]}"
PORT="${ADDR[1]}"

exec /dist/OBJ-PATH/bin/tstclnt -D -V tls1.3:tls1.3 -o -O -h $HOST -p $PORT -v -A /httpreq.txt -L 2 "$@"
