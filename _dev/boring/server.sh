#!/bin/sh
PATH=/boringssl/build/tool:$PATH
set -x

# RSA
bssl server \
    -key rsa.pem \
    -min-version tls1.2 -max-version tls1.3 \
    -tls13-variant draft28 \
    -accept 1443 -loop -www 2>&1 &

# ECDSA
bssl server \
    -key ecdsa.pem \
    -min-version tls1.2 -max-version tls1.3 \
    -tls13-variant draft28 \
    -accept 2443 -loop -www 2>&1 &

# Require client authentication (with ECDSA)
bssl server \
    -key ecdsa.pem \
    -min-version tls1.2 -max-version tls1.3 \
    -tls13-variant draft28 \
    -accept 6443 -loop -www \
    -require-any-client-cert -debug 2>&1 &

wait
