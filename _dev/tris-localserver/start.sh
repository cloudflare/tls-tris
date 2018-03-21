#! /bin/sh
set -e

exec docker run --name tris-localserver --env TLSDEBUG=error "$@" tris-localserver

