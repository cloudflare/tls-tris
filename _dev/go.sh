#!/usr/bin/env bash
set -e

BASEDIR=$(cd "$(dirname "$0")" && pwd)

make --quiet -C "$BASEDIR" go >&2
GOENV="$(go env GOOS)_$(go env GOARCH)"

GO="$BASEDIR/go_$GOENV/bin/go" make --quiet -C "$BASEDIR" GOROOT >&2
export GOROOT="$BASEDIR/GOROOT/$GOENV"

exec $BASEDIR/go_$GOENV/bin/go "$@"
