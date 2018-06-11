# Generating self-signed test keys

Use the program `generate_cert.go` in the `crypto/tls` directory:
```
_dev/go.sh run generate_cert.go -ecdsa-curve P256 -host example.com -dc
```

To get a certificate without the DelegationUsage extension, remove the `-dc`
parameter.
