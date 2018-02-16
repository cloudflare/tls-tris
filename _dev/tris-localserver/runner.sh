#!/bin/sh

./tris-localserver -b 0.0.0.0:1443 -palg=ecdsa -rtt0=n  2>&1 &  # first port: ECDSA (and no 0-RTT)
./tris-localserver -b 0.0.0.0:2443 -palg=rsa   -rtt0=a  2>&1 &  # second port: RSA (and accept 0-RTT but not offer it)
./tris-localserver -b 0.0.0.0:3443 -palg=ecdsa -rtt0=o  2>&1 &  # third port: offer and reject 0-RTT
./tris-localserver -b 0.0.0.0:4443 -palg=ecdsa -rtt0=oa 2>&1 &  # fourth port: offer and accept 0-RTT
./tris-localserver -b 0.0.0.0:5443 -palg=ecdsa -rtt0=oa -rtt0ack 2>&1 &  # fifth port: offer and accept 0-RTT but confirm
./tris-localserver -b 0.0.0.0:6443 -palg=rsa   -cliauth 2>&1 &  # sixth port: RSA with required client authentication

wait
