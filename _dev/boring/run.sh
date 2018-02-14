#! /bin/sh
set -e

/boringssl/build/tool/bssl client -grease -min-version tls1.3 -max-version tls1.3 \
	-tls13-variant draft22 -session-out /session \
    -key client_rsa.key -cert client_rsa.pem \
    -connect "$@" < /httpreq.txt
exec /boringssl/build/tool/bssl client -grease -min-version tls1.3 -max-version tls1.3 \
	-tls13-variant draft22 -session-in /session \
    -key client_rsa.key -cert client_rsa.pem \
    -connect "$@" < /httpreq.txt
