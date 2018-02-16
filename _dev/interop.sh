#!/usr/bin/env bash
set -xeuo pipefail

if [ "$1" = "INSTALL" ]; then
		# INSTALL <client> [<revision>]
		if [ -n "${3:-}" ]; then
				REVISION="--build-arg REVISION=$3"
		else
				REVISION=""
		fi
		docker build $REVISION -t tls-tris:$2 _dev/$2

elif [ "$1" = "RUN" ]; then
		# RUN <client>
		IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver)

		docker run --rm tls-tris:$2 $IP:1443 | tee output.txt # RSA
		grep "Hello TLS 1.3" output.txt | grep -v "resumed" | grep -v "0-RTT"
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"

		docker run --rm tls-tris:$2 $IP:2443 | tee output.txt # ECDSA
		grep "Hello TLS 1.3" output.txt | grep -v "resumed" | grep -v "0-RTT"
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"



elif [ "$1" = "0-RTT" ]; then
		# 0-RTT <client>
		IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver)

		docker run --rm tls-tris:$2 $IP:3443 | tee output.txt # rejecting 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"

		docker run --rm tls-tris:$2 $IP:4443 | tee output.txt # accepting 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep "0-RTT"

		docker run --rm tls-tris:$2 $IP:5443 | tee output.txt # confirming 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep "0-RTT confirmed"

elif [ "$1" = "INSTALL-CLIENT" ]; then
		cd "$(dirname "$0")/tris-testclient"
		./build.sh

elif [ "$1" = "RUN-CLIENT" ]; then
		# RUN-CLIENT <target-server>
		cd "$(dirname "$0")/tris-testclient"

		SERVERNAME="$2-localserver"
		docker run --rm --detach --name "$SERVERNAME" \
			--entrypoint /server.sh \
			--expose 1443 --expose 2443 --expose 6443 \
			tls-tris:$2
		IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' "$SERVERNAME")
		# Obtain information and stop server on exit
		trap 'docker ps -a; docker logs "$SERVERNAME"; docker kill "$SERVERNAME"' EXIT

		# RSA
		docker run --rm tris-testclient -ecdsa=false $IP:1443
		# ECDSA
		docker run --rm tris-testclient -rsa=false $IP:2443

		# Test client authentication if requested
		[[ $3 =~ .*C.* ]] && docker run --rm tris-testclient -rsa=false -cliauth $IP:6443; true

		# TODO maybe check server logs for expected output?
fi
