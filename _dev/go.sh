#!/usr/bin/env bash
set -e

BASEDIR=$(cd "$(dirname "$0")" && pwd)

make --quiet -C "$BASEDIR" go >&2
GOENV="$(go env GOOS)_$(go env GOARCH)"

unset GOROOT
make --quiet -C "$BASEDIR" GOROOT GO="$BASEDIR/go/$GOENV/bin/go" >&2
export GOROOT="$BASEDIR/GOROOT/$GOENV"

exec $BASEDIR/go/$GOENV/bin/go "$@"
