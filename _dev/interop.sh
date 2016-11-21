#!/usr/bin/env bash
set -xeuo pipefail

if [ "$1" = "INSTALL" ]; then
		if [ -n "${3:-}" ]; then
				REVISION="--build-arg REVISION=$3"
		else
				REVISION=""
		fi
		docker build $REVISION -t tls-tris:$2 _dev/$2

elif [ "$1" = "RUN" ]; then
		IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver)
		docker run --rm tls-tris:$2 $IP:$3 | tee output.txt
		grep "Hello TLS 1.3" output.txt | grep -v "resumed"
		grep "Hello TLS 1.3" output.txt | grep "resumed"

fi
