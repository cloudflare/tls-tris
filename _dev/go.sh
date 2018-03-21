#!/usr/bin/env bash
# 
# THIS FILE IS ONLY USED BY _dev/bogo. It will be removed in future
set -e

BASEDIR=$(cd "$(dirname "$0")" && pwd)
GOENV="$(go env GOHOSTOS)_$(go env GOHOSTARCH)"

BUILD_DIR=${BASEDIR}/GOROOT make -f $BASEDIR/Makefile >&2

export GOROOT="$BASEDIR/GOROOT/$GOENV"
exec go "$@"
