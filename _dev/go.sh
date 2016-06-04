#!/usr/bin/env bash

BASEDIR=$(cd "$(dirname "$0")" && pwd)

make --quiet -C "$BASEDIR" GOROOT/.ok
export GOROOT="$BASEDIR/GOROOT"

exec go "$@"
