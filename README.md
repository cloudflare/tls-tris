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

Since we assume that if you are using tls-tris you want 1.3, a hardcoded MaxVersion
of 1.2 is overridden to 1.3 automatically.

## Running the NSS test client

```
go run generate_cert.go -ecdsa-curve P256 -host 192.168.64.1 -duration 87600h
make -C _dev bin/tris-localserver
TLSDEBUG=1 ./_dev/bin/tris-localserver 192.168.64.1:4433
```

```
docker build -t tstclnt _dev/tstclnt
docker run -it tstclnt -D -V tls1.3:tls1.3 -o -O -h 192.168.64.1 -p 4433
```

## Testing with Firefox

1. Download the latest Firefox Nightly
1. Navigate to about:config and set `security.tls.version.max` to `4`
1. Navigate to https://tris.filippo.io/

