#! /bin/sh

/boringssl/build/tool/bssl s_client -min-version tls1.3 -max-version tls1.3 -connect "$@" < /httpreq.txt
