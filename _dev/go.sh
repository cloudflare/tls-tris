#!/usr/bin/env bash

BASEDIR=$(cd "$(dirname "$0")" && pwd)

make --quiet -C "$BASEDIR" GOROOT
export GOROOT="$BASEDIR/GOROOT"

exec go "$@"
