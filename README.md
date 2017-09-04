```
 _____ _     ____        _        _
|_   _| |   / ___|      | |_ _ __(_)___
  | | | |   \___ \ _____| __| '__| / __|
  | | | |___ ___) |_____| |_| |  | \__ \
  |_| |_____|____/       \__|_|  |_|___/

```

crypto/tls, now with 100% more 1.3.

THE API IS NOT STABLE AND DOCUMENTATION IS NOT GUARANTEED.

[![Build Status](https://travis-ci.org/cloudflare/tls-tris.svg?branch=master)](https://travis-ci.org/cloudflare/tls-tris)

## Usage

Since `crypto/tls` is very deeply (and not that elegantly) coupled with the Go stdlib,
tls-tris shouldn't be used as an external package.  It is also impossible to vendor it
as `crypto/tls` because stdlib packages would import the standard one and mismatch.

So, to build with tls-tris, you need to use a custom GOROOT.
A script is provided that will take care of it for you: `./_dev/go.sh`.
Just use that instead of the `go` tool.

The script also transparently fetches the custom Cloudflare Go 1.9 compiler with the required backports.

```
./_dev/go.sh build ./_dev/tris-localserver
TLSDEBUG=error ./tris-localserver 127.0.0.1:4443
```

## Debugging

When the environment variable `TLSDEBUG` is set to `error`, Tris will print a hexdump of the Client Hello and a stack trace if an handshake error occurs. If the value is `short`, only the error and the first meaningful stack frame are printed.

## Building Caddy

```
./_dev/go.sh build github.com/mholt/caddy
```

*Note: to get Caddy to use TLS 1.3 you'll have to apply the patch at `_dev/caddy/caddy.patch`.*

## Testing with BoringSSL/NSS/Mint/...

```
./_dev/tris-localserver/start.sh --rm
```

```
docker build -t tls-tris:boring _dev/boring
docker run -i --rm tls-tris:boring $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```

```
docker build -t tls-tris:tstclnt _dev/tstclnt
docker run -i --rm tls-tris:tstclnt $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```

```
docker build -t tls-tris:mint _dev/mint
docker run -i --rm tls-tris:mint $(docker inspect -f '{{ .NetworkSettings.IPAddress }}' tris-localserver):443
```

To build a specific revision, use `--build-arg REVISION=abcdef1234`.
