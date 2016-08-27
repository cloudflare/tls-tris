#!/usr/bin/env bash
set -e

BASEDIR=$(cd "$(dirname "$0")" && pwd)

make --quiet -C "$BASEDIR" go/bin/go >&2

GO="$BASEDIR/go/bin/go" make --quiet -C "$BASEDIR" GOROOT >&2
export GOROOT="$BASEDIR/GOROOT"

exec $BASEDIR/go/bin/go "$@"
