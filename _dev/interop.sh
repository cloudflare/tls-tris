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

		docker run --rm tls-tris:$2 $IP:1443 | tee output.txt # RSA
		grep "Hello TLS 1.3" output.txt | grep -v "resumed" | grep -v "0-RTT"
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"

		docker run --rm tls-tris:$2 $IP:2443 | tee output.txt # ECDSA
		grep "Hello TLS 1.3" output.txt | grep -v "resumed" | grep -v "0-RTT"
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"

elif [ "$1" = "0-RTT" ]; then
		IP=$(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver)

		docker run --rm tls-tris:$2 $IP:3443 | tee output.txt # rejecting 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep -v "0-RTT"

		docker run --rm tls-tris:$2 $IP:4443 | tee output.txt # accepting 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep "0-RTT"

		docker run --rm tls-tris:$2 $IP:5443 | tee output.txt # confirming 0-RTT
		grep "Hello TLS 1.3" output.txt | grep "resumed" | grep "0-RTT confirmed"

fi
