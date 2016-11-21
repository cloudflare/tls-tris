#! /bin/sh
set -e

/boringssl/build/tool/bssl client -grease -min-version tls1.3 -max-version tls1.3 \
	-session-out /session -connect "$@" < /httpreq.txt
exec /boringssl/build/tool/bssl client -grease -min-version tls1.3 -max-version tls1.3 \
	-session-in /session -connect "$@" < /httpreq.txt

