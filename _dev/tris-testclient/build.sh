#!/bin/sh
set -e
cd "$(dirname "$0")"
GOOS=linux ../go.sh build -v -i .
docker build -t tris-testclient .
