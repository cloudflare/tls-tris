#!/usr/bin/env bash
set -e

BASEDIR=$(cd "$(dirname "$0")" && pwd)
GOENV="$(go env GOHOSTOS)_$(go env GOHOSTARCH)"

make --quiet -C "$BASEDIR" GOROOT >&2

export GOROOT="$BASEDIR/GOROOT/$GOENV"
exec go "$@"
