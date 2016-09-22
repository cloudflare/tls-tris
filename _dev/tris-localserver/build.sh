#! /bin/sh
set -e

cd "$(dirname $0)"

GOOS=linux ../go.sh build -v -i .
docker build -t tris-localserver .
docker run --name tris-localserver --env TLSDEBUG=error --rm tris-localserver

