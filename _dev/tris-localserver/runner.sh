#!/bin/sh

./tris-localserver -b 0.0.0.0:1443 -cert=rsa   -rtt0=n  2>&1 &  # first port: ECDSA (and no 0-RTT)
./tris-localserver -b 0.0.0.0:2443 -cert=ecdsa -rtt0=a  2>&1 &  # second port: RSA (and accept 0-RTT but not offer it)
./tris-localserver -b 0.0.0.0:3443 -cert=ecdsa -rtt0=o  2>&1 &  # third port: offer and reject 0-RTT
./tris-localserver -b 0.0.0.0:4443 -cert=ecdsa -rtt0=oa 2>&1 &  # fourth port: offer and accept 0-RTT
./tris-localserver -b 0.0.0.0:5443 -cert=ecdsa -rtt0=oa -rtt0ack 2>&1 &  # fifth port: offer and accept 0-RTT but confirm
./tris-localserver -b 0.0.0.0:6443 -cert=rsa   -cliauth 2>&1 &  # sixth port: RSA with required client authentication
./tris-localserver -b 0.0.0.0:7443 -cert=ecdsa -pq=c &          # Enables support for both - post-quantum and classical KEX algorithms

wait
