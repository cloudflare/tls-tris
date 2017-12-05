#!/bin/sh
PATH=/dist/OBJ-PATH/bin:$PATH
set -x

# RSA
selfserv -n rsa-server   -p 1443 -d /certdb -V tls1.2:tls1.3 -v -Z &

# ECDSA
selfserv -n ecdsa-server -p 2443 -d /certdb -V tls1.2:tls1.3 -v -Z &

wait
