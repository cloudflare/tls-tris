package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

var cipherSuiteIdToName = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

var namedGroupsToName = map[uint16]string{
	uint16(tls.HybridSIDHp503Curve25519): "X25519-SIDHp503",
	uint16(tls.HybridSIKEp503Curve25519): "X25519-SIKEp503",
	uint16(tls.X25519):                   "X25519",
	uint16(tls.CurveP256):                "P-256",
	uint16(tls.CurveP384):                "P-384",
	uint16(tls.CurveP521):                "P-521",
}

func getIDByName(m map[uint16]string, name string) (uint16, error) {
	for key, value := range m {
		if value == name {
			return key, nil
		}
	}
	return 0, errors.New("Unknown value")
}

var failed uint

type Client struct {
	TLS  tls.Config
	addr string
}

func NewClient() *Client {
	var c Client
	c.TLS.InsecureSkipVerify = true
	return &c
}

func (c *Client) clone() *Client {
	var clone Client
	clone.TLS = *c.TLS.Clone()
	clone.addr = c.addr
	return &clone
}

func (c *Client) setMinMaxTLS(ver uint16) {
	c.TLS.MinVersion = ver
	c.TLS.MaxVersion = ver
}

func (c *Client) run() {
	fmt.Printf("TLS %s with %s\n", tlsVersionToName[c.TLS.MinVersion], cipherSuiteIdToName[c.TLS.CipherSuites[0]])

	con, err := tls.Dial("tcp", c.addr, &c.TLS)
	if err != nil {
		fmt.Printf("handshake failed: %v\n\n", err)
		failed++
		return
	}
	defer con.Close()

	_, err = con.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		fmt.Printf("Write failed: %v\n\n", err)
		failed++
		return
	}

	buf := make([]byte, 1024)
	n, err := con.Read(buf)
	// A non-zero read with EOF is acceptable and occurs when a close_notify
	// is received right after reading data (observed with NSS selfserv).
	if !(n > 0 && err == io.EOF) && err != nil {
		fmt.Printf("Read failed: %v\n\n", err)
		failed++
		return
	}
	fmt.Printf("[TLS: %s] Read %d bytes\n", tlsVersionToName[con.ConnectionState().Version], n)
	fmt.Println("OK\n")
}

func result() {
	if failed > 0 {
		log.Fatalf("Failed handshakes: %d\n", failed)
	} else {
		fmt.Println("All handshakes passed")
	}
}

// Usage client args host:port
func main() {
	var keylog_file, tls_version, named_groups, named_ciphers string
	var enable_rsa, enable_ecdsa, client_auth bool

	flag.StringVar(&keylog_file, "keylogfile", "", "Secrets will be logged here")
	flag.BoolVar(&enable_rsa, "rsa", true, "Whether to enable RSA cipher suites")
	flag.BoolVar(&enable_ecdsa, "ecdsa", true, "Whether to enable ECDSA cipher suites")
	flag.BoolVar(&client_auth, "cliauth", false, "Whether to enable client authentication")
	flag.StringVar(&tls_version, "tls_version", "1.3", "TLS version to use")
	flag.StringVar(&named_groups, "groups", "X25519:P-256:P-384:P-521", "NamedGroups IDs to use")
	flag.StringVar(&named_ciphers, "ciphers", "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "Named cipher IDs to use")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	client := NewClient()
	client.addr = flag.Arg(0)
	if !strings.Contains(client.addr, ":") {
		client.addr += ":443"
	}

	if keylog_file == "" {
		keylog_file = os.Getenv("SSLKEYLOGFILE")
	}
	if keylog_file != "" {
		keylog_writer, err := os.OpenFile(keylog_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		client.TLS.KeyLogWriter = keylog_writer
		log.Println("Enabled keylog")
	}

	if client_auth {
		var err error
		client_cert, err := tls.X509KeyPair([]byte(client_crt), []byte(client_key))
		if err != nil {
			panic("Can't load client certificate")
		}

		client.TLS.Certificates = []tls.Certificate{client_cert}
		client.TLS.RootCAs = x509.NewCertPool()
		if !client.TLS.RootCAs.AppendCertsFromPEM([]byte(client_ca)) {
			panic("Can't load client CA cert")
		}
	}

	if enable_rsa {
		// Sanity check: TLS 1.2 with the mandatory cipher suite from RFC 5246
		c := client.clone()
		c.TLS.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
		c.setMinMaxTLS(tls.VersionTLS12)
		c.run()
	}

	if enable_ecdsa {
		// Sane cipher suite for TLS 1.2 with an ECDSA cert (as used by boringssl)
		c := client.clone()
		c.TLS.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		c.setMinMaxTLS(tls.VersionTLS12)
		c.run()
	}

	// Set requested DH groups
	client.TLS.CurvePreferences = []tls.CurveID{}
	for _, ng := range strings.Split(named_groups, ":") {
		id, err := getIDByName(namedGroupsToName, ng)
		if err != nil {
			panic("Wrong group name provided")
		}
		client.TLS.CurvePreferences = append(client.TLS.CurvePreferences, tls.CurveID(id))
	}

	// Perform TLS handshake with each each requested CipherSuite
	tlsID, err := getIDByName(tlsVersionToName, tls_version)
	if err != nil {
		panic("Unknown TLS version")
	}
	for _, cn := range strings.Split(named_ciphers, ":") {
		id, err := getIDByName(cipherSuiteIdToName, cn)
		if err != nil {
			panic("Wrong cipher name provided")
		}
		client.setMinMaxTLS(tlsID)
		client.TLS.CipherSuites = []uint16{id}
		client.run()
	}

	// TODO test other kex methods besides X25519, like MTI secp256r1
	// TODO limit supported groups?

	result()
}

const (
	client_ca = `-----BEGIN CERTIFICATE-----
MIIF6zCCA9OgAwIBAgIUC4U4HlbkVMrKKTFK0mNrMFDpRskwDQYJKoZIhvcNAQEL
BQAwfTELMAkGA1UEBhMCRlIxDTALBgNVBAgMBFBBQ0ExFzAVBgNVBAcMDkNhZ25l
cyBzdXIgTWVyMSIwIAYDVQQLDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9uMSIw
IAYDVQQDDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9uMB4XDTE5MDIyMjAwNDIz
OVoXDTQ2MDcwOTAwNDIzOVowfTELMAkGA1UEBhMCRlIxDTALBgNVBAgMBFBBQ0Ex
FzAVBgNVBAcMDkNhZ25lcyBzdXIgTWVyMSIwIAYDVQQLDBlDZXJ0IFRlc3Rpbmcg
T3JnYW5pemF0aW9uMSIwIAYDVQQDDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9u
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0z+DMLb7YIMFFNZpn+ve
NdT7GL9DPyV9ZWSHpUuDyme6Og6Mp5IpCLlKjNXtizX5aQ9xQ746slt70fivSV/r
tiEtayZkcwS7zHtc5f+U/S0hR1q5Zh3DaLQH9diSeuNFQN5pg7zQT5csJFlxf6EB
j/ioSBC+J1E8A2FAh0qDq+TvPPyZEEjcJy0oBuNHUnkC3rwjt24DAUI26rN/Qk9P
a6KR9bBOdHFFul3DEP/uPqWV9TvV5tJhP3J2RbfS79WljFy/lFIwvJvfQHYEjMt4
/gq8yTSUgJ8zmgJQ1sgOKH1FzJd4EdAMquSYbElkc35jX8gggUNOUcwsIfJBnu41
SC51JQruNT256zse76o8Dx3lSHiz5c6luZyJnZWWt6xWtfGEGMnckpn6cVvcbbgq
eWqmttgE2QTpgYoYUVcX/XFtsmZVTu05r8MZoqje5rgW9nEvvW+3M+eT5h0M9eGQ
bIT3D3tdXB2XWCjUWqxpZscFwyumGu7vdykBKLhMVR3nEpFfORnH+534vwi49fjz
WnN6fXAZZLPnGtEdWXNgs9JtgI5UheAQbcA3FT+M3maa88V2JrETLps405NYp6hJ
6msbS/AmV/eSilRmbGVj9TfKHb/BVHNYwVQ0Bu/QN2YQNQ9olOpIxXgKr6Y4tKZt
wTOMiCxZrnDQneQOTnW0NAMCAwEAAaNjMGEwHQYDVR0OBBYEFNLiS6YezH2bWiZ3
TNbkQzMoBBB2MB8GA1UdIwQYMBaAFNLiS6YezH2bWiZ3TNbkQzMoBBB2MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAQ
cWIFOusSLKizqcqMsbMIY/Jzy0Tq5jzeOAQEQBztu7eJb208SG2EJtD6ylBQCF8t
FCxUbvWNrly1MJoMSXdn3uMz3kLKNQa6RENckwA1UuYZpdhvTUtmPun9QqFPJdqm
oi0paOVut9q3dplDy6MUknGN4tNWp2ZDfyvom3mUMfYGEO/FCWTy8eFd6cHRE9bw
tHkcX5r7GpDHH5vKXOF/deMp1Xgep5ZTasL13YwPiYgctst91pEfdcztjHW0mQNT
ZH/TUQDgs2UCjcvyeOlgoZixWOpkf1Qyje15k9qMb89/5hdarxvAQbG2BezQtzyk
bbCu1MQa2DBdAKbhQxas/DPSvSkA/y8v+hiovTWtPKErPnQqZqVy59KUTBWj8ZAj
5dkDVjBvUcsJ/6zHv0X9puEnIDZ8pK+Xn9LbcbPE7Nf1ikDyOqHmLmhGfWlEGvoD
3Q8f8zUySZ40mfqtVhc7OYqA66Q9quNQ4VBESVNiEJ/LuWHRXe74KqFdggsQqtS6
UQQgw5lFnKHZ9pk2VlKzgpkmd5fLMOhcHWQbsah9TFOuW5vEhWGHNhGCyGouWTzD
mkwlPS8arj/ymUn6t/oiwSOA6GbjQLnTXvoAjdBxnukQlNY6TUDk+lSQw0qfZGIA
xZywUgRbLZH8TFUnuEQps35XnWrY8rrXVj9+9h0B4g==
-----END CERTIFICATE-----`
	client_crt = `-----BEGIN CERTIFICATE-----
MIIFSjCCAzKgAwIBAgIUCKk2npLYEX2Z3Ceu1CwSKK50j04wDQYJKoZIhvcNAQEL
BQAwfTELMAkGA1UEBhMCRlIxDTALBgNVBAgMBFBBQ0ExFzAVBgNVBAcMDkNhZ25l
cyBzdXIgTWVyMSIwIAYDVQQLDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9uMSIw
IAYDVQQDDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9uMB4XDTE5MDIyMjAwNDMz
MloXDTQ2MDcwOTAwNDMzMlowfTELMAkGA1UEBhMCRlIxDTALBgNVBAgMBFBBQ0Ex
FzAVBgNVBAcMDkNhZ25lcyBzdXIgTWVyMSIwIAYDVQQLDBlDZXJ0IFRlc3Rpbmcg
T3JnYW5pemF0aW9uMSIwIAYDVQQDDBlDZXJ0IFRlc3RpbmcgT3JnYW5pemF0aW9u
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA0DQrWlCfijylutz28aTB
T9WDnvBWpJ535t/Clt4o2nv3Cp6JxvUVzYkdKuaLR295gyEBx9JSHiZxPiJoPVfp
wigmG0R9HvByAG5rhaQbQt99npoBaHMps1i12VxxFy1yaqZW6mrwrHMfV716rZ2M
AzWx7UfhutloBYeeluiziDWUSEuGeJG7kHdvUtGYlbRd/ElFWHOfAQ7Oc8UUjEHW
sorkqciqyAERV/H9hr5Rap/J/ERcFC8bNecS4t1Yh98WgIun/MbcBKQzo1LsWmOQ
dmaMBoG8g1mYRbNap8G/+aQbjfRi1zN0yaW1wtlLoBJmNgLjwYgaS/5Uey5NZMdb
NwIBA6OBwzCBwDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAxBglghkgB
hvhCAQ0EJBYiQ2VydCBUZXN0aW5nIEludGVybWVkaWF0ZSAtIENsaWVudDAdBgNV
HQ4EFgQULlrGFPbxwz525ywQYPs72P7YnL4wHwYDVR0jBBgwFoAU0uJLph7MfZta
JndM1uRDMygEEHYwDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAgEAwLc+Xg5Fyfbgu5iFs1y7E0Et
4E/5lF0A4iqDVX3e7/upoUIBFZFv2PlAqIlhQ49NgGlIfrBlwEijZJ9kgVmUcKDS
UrqBvKUn+99dTC8Zn/Py9ofLNcJy+qNJg4TpbpBxXaP1MXdZYXdYkGtyyPIGo31U
oHibNLQDCtKFMoEPCvFuCBtJgyT46l5KN7VQCA0ZDm84fVmIgEEOXWwz0mDIhGWm
hDhmqONznl0+aHirqJxsBaplBaFVV1N02ksR53sPPy/UfDsAD3Fpp8R1DAMEyy0o
kTqm8QINVL961YT1Y/oI+GlypjPq9cL0dEHdxwu6gyCHPMMGGGIDHmLoqJJuj/Kr
/T08jhtDv8D7e9m3wfSW/RqHKE31Yy21SXv/gpcHGunwzDoj/QUvRl/xTjJfx+S8
2NHxSU8QOdexhJumsNFJe8kH8cRJMCMB8/hfiBpI0QANkUBJ1aaa/p7vZuEKJm+/
85m3Yz+zn58/Bube06z6QzFeR8Edi+6hXk4/WoHltgXiNowD3d4xI48sPWEbe+QZ
6u60sEdpY2a+3Xwt9m9R2R+sGP3QyDFd9GVaUPt21TeeLdfS3kPqwO2k+UXB8nV3
Yh1Hvyx67u0tX3wBVe40CNaAu7iW+e4aXjksG2dxk71lNq5CHJCOtbRK4LUArjy5
cw4KAXWoaR8YIC3BWgg=
-----END CERTIFICATE-----`
	client_key = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQNCtaUJ+KPKW6
3PbxpMFP1YOe8Faknnfm38KW3ijae/cKnonG9RXNiR0q5otHb3mDIQHH0lIeJnE+
Img9V+nCKCYbRH0e8HIAbmuFpBtC332emgFocymzWLXZXHEXLXJqplbqavCscx9X
vXqtnYwDNbHtR+G62WgFh56W6LOINZRIS4Z4kbuQd29S0ZiVtF38SUVYc58BDs5z
xRSMQdayiuSpyKrIARFX8f2GvlFqn8n8RFwULxs15xLi3ViH3xaAi6f8xtwEpDOj
UuxaY5B2ZowGgbyDWZhFs1qnwb/5pBuN9GLXM3TJpbXC2UugEmY2AuPBiBpL/lR7
Lk1kx1s3AgEDAoIBAQCKzXI8Nb+xfcPR6KShGIDf460UoDnDFE/vP9cPPsXm/U9c
abEvTg6JBhNx7weE9PuswKvajDa+xEt+wZrTj/EsGsQSLai/Svaq9EeubWeB6lO/
EVZFohvM5c6Q6EtkyPbxxDnxnKBy92o6flHJE7KsznaeL+vR5kVZBRRkmyJazS4s
Z5rbrN9AhSIfyHs9GCQGgsXT6HMsyoJYFastwQ2qj+9L2ypcM8TW+KGzGfJipoJb
l/N/8WHb4ZumA67lfWq4v5JTA5qAUKcfPszEBrUfQ34Tk+73Iiov9f7SXPYxWxVJ
g9PuzfewvJrp6CPv+/mKNt8PmBYkaXlnyjr9tCwLAoGBAPjAVZapQVuIqftcOZtf
Re9fAV9Vvv1FEO8bKJeIsPDlRkdg+TfTMgxhZU0I3P4XdEj7Fa87w4wkA6GkIrOO
W9/usPOYzSdTP5aVEsdGbT8yD2vTST7Aw/GESKTRJA/Fe1PIb5Nz3OijyTusvFE+
XSR3EXb1myX+2rFS0Wbiz2U5AoGBANZFWoeFzREnBcDG60RayjiTg71E1/T4zhvU
e/w+71FNbLZXBrNqgV20F73xOme/Mb13yr+YgXxIEQfFtR6hRxZ8u1jndEzw66Jf
YfHt7EGVceMV2pdP4md5ebebEj7qICfXPxF9IZicwZG3QMR5u0tvnx40iNMWhW0M
rY4FabPvAoGBAKXVjmRw1j0FxqeS0RI/g/TqAOo5Kf4uC0oSGw+wdfXuLtpApiU3
drLrmN4F6Klk+DCnY8on17LCrRZtbHe0PT/0dfe7M2+M1Q8ODITZniohX503hinV
1/ZYMG3gwrUuUjfa9Qz36JsX230d0uDUPhhPYPn5EhlUkcuMi5nsikN7AoGBAI7Y
5wUD3gtvWSsvR4LnMXsNAn4t5U37NBKNp/1/SjYznc7kryJHAOkiun6g0Zp/dn5P
3H+7AP2FYK/ZI2nA2g790jtE+DNLR8GU6/aenYEOS+y5PGTf7ET7pnpnYX9GwBqP
f2D+FmW91mEk1dhRJ4efv2l4WzdkWPNdyQlY8SKfAoGAEIWmowo7EpbR5Boxc2o3
Tl0JbGi1CNJAHtDjEJCd1OxKrMUrK07hOeEKF6y8K/WBuQhFvI2pu16oT4sMal9Z
mEiJdJAFErefPLQGomHLXfq9mDEY13Ug/xAd9aMyYcubIg5XjAqLMrB60HcrLr7Q
2hMCSDdVP2V/F3QVh8DEirE=
-----END PRIVATE KEY-----`
)
