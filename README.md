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

## Important: custom compiler

tls-tris will only build with the modified Go compiler you'll find here:

https://github.com/cloudflare/go/tree/1.7

Simply clone that repository at that branch, run `make.bash` in `src/`,
and then run the following command in each shell before using tls-tris.

```
export PATH="/path/to/cloudflare/go/bin:$PATH"
```

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

*Note: to get Caddy to use TLS 1.3 you'll have to apply the patch at `_dev/caddy/caddy.patch`.*

## Debugging

The environment variable `TLSDEBUG` has three recognized values:

  * `live`: print to stderr a handshake trace and error stacks
  * `keys`: like `live`, but also print key material and derivation steps
  * `error`: like `live`, but only dump to stderr if an error occurs

## Running the NSS test client

```
go run generate_cert.go -ecdsa-curve P256 -host 192.168.64.1 -duration 87600h
./_dev/go.sh build -i -v ./_dev/tris-localserver
./_dev/bin/tris-localserver 192.168.64.1:4433
```

```
docker build -t tstclnt _dev/tstclnt
docker run -i tstclnt -D -V tls1.3:tls1.3 -o -O -h 192.168.64.1 -p 4433
```

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
