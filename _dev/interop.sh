#!/usr/bin/env bash
set -xeuo pipefail

IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver)

docker run -i --rm filosottile/tls-tris:$1 $IP:$2 | tee output.txt
grep "Hello TLS 1.3" output.txt
