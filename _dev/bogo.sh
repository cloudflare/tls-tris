#!/usr/bin/env bash
set -xeuo pipefail

BASEDIR=$(cd "$(dirname "$0")" && pwd)

docker build -t tls-tris:bogo _dev/bogo
docker run --rm -v $BASEDIR/..:/go/src/github.com/cloudflare/tls-tris tls-tris:bogo
