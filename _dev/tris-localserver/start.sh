#! /bin/sh
set -e

cd "$(dirname $0)"

CGO_ENABLED=0 GOOS=linux ../go.sh build -v -i .
docker build -t tris-localserver .
exec docker run --name tris-localserver --env TLSDEBUG=error "$@" tris-localserver

