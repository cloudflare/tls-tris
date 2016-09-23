```
 _____ _     ____        _        _
|_   _| |   / ___|      | |_ _ __(_)___
  | | | |   \___ \ _____| __| '__| / __|
  | | | |___ ___) |_____| |_| |  | \__ \
  |_| |_____|____/       \__|_|  |_|___/

```

crypto/tls, now with 100% more 1.3.

DO NOT USE THIS FOR THE SAKE OF EVERYTHING THAT'S GOOD AND JUST.

[![Build Status](https://travis-ci.org/cloudflare/tls-tris.svg?branch=master)](https://travis-ci.org/cloudflare/tls-tris)

## Usage

Since `crypto/tls` is very deeply (and not that elegantly) coupled with the Go stdlib,
tls-tris shouldn't be used as an external package.  It also is impossible to vendor it
as `crypto/tls` because stdlib packages would import the standard one and mismatch.

So, to build with tls-tris, you need to use a custom GOROOT.
A script is provided that will take care of it for you: `./_dev/go.sh`.
Just use that instead of the `go` tool.

```
./_dev/go.sh build github.com/mholt/caddy
```

The script also transparently fetches the modified custom CloudFlare Go compiler.

*Note: to get Caddy to use TLS 1.3 you'll have to apply the patch at `_dev/caddy/caddy.patch`.*

## Debugging

The environment variable `TLSDEBUG` has one recognized values:

  * `error`: if an handshake error occurs, print the CH and stack trace

## Testing with Firefox

1. Download the latest Firefox Nightly
1. Navigate to about:config and set `security.tls.version.max` to `4`
1. Navigate to https://tris.filippo.io/

## Testing with mint

```
go run generate_cert.go -ecdsa-curve P256 -host localhost -duration 87600h
./_dev/go.sh build ./_dev/tris-localserver
./_dev/bin/tris-localserver 127.0.0.1:4433
```

```
go build github.com/bifurcation/mint/bin/mint-client-https
./mint-client-https -url https://localhost:4433
```

## Testing with BoringSSL/BoGo/NSS

```
./_dev/tris-localserver/build.sh
```

```
docker build -t bssl _dev/boring
docker run -i --rm bssl $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```

```
docker build -t bogo _dev/bogo
docker run -i --rm bogo $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```

```
docker build -t tstclnt _dev/tstclnt
docker run -i --rm tstclnt $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```
