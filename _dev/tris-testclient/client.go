package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10:        "1.0",
	tls.VersionTLS11:        "1.1",
	tls.VersionTLS12:        "1.2",
	tls.VersionTLS13:        "1.3",
	tls.VersionTLS13Draft28: "1.3 (draft 28)",
}

var cipherSuiteIdToName = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
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
	fmt.Printf("Read %d bytes\n", n)

	fmt.Println("OK\n")
}

func result() {
	if failed > 0 {
		log.Fatalf("Failed handshakes: %d\n", failed)
	} else {
		fmt.Println("All handshakes passed")
	}
}

func main() {
	var keylog_file string
	var enable_rsa, enable_ecdsa, client_auth bool

	flag.StringVar(&keylog_file, "keylogfile", "", "Secrets will be logged here")
	flag.BoolVar(&enable_rsa, "rsa", true, "Whether to enable RSA cipher suites")
	flag.BoolVar(&enable_ecdsa, "ecdsa", true, "Whether to enable ECDSA cipher suites")
	flag.BoolVar(&client_auth, "cliauth", false, "Whether to enable client authentication")
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

	client.setMinMaxTLS(tls.VersionTLS13)
	client.TLS.CipherSuites = []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}
	client.run()

	client.setMinMaxTLS(tls.VersionTLS13)
	client.TLS.CipherSuites = []uint16{tls.TLS_AES_128_GCM_SHA256}
	client.run()

	client.setMinMaxTLS(tls.VersionTLS13)
	client.TLS.CipherSuites = []uint16{tls.TLS_AES_256_GCM_SHA384}
	client.run()

	// TODO test other kex methods besides X25519, like MTI secp256r1
	// TODO limit supported groups?

	result()
}

const (
	client_ca = `-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIJAPpBgIvtQb1EMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTgwMjEzMjAxNjA3WhcNMTkwMjEzMjAxNjA3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAr4xgdmB4DaEh8zRFmg/1ZxYhQZMUP0iQX/Y8nDWxNlcd42p3TgpY1biz
jrq58ln9Om4U/GAn2RmtBAynSBXIlR5oVa44JeMM8Ka8R/dMKyHpF0Nj2EJB9unb
TC33PfzOlnKQxATwevnnhI6tGluWmwvxXUi7WnX0di+nQg9HrIVom3KrmRr2/41y
g497ccYUuNnKE6sewGdGzw045oWZpMDA2Us+MFo1IywOurjaM9bueRhPTcIiQ8RE
h7qb+FRwfxaj9ynZA2PCM7WMSSWCiZJV0uj/pshYF2lvtJcJef4dhwnsYBpc+mgx
2q9qcUBeo3ZHbi1/PRqjwSmcW3yY5cQRbpYp6xFmgmX3oHQkVXS0UlpNVZ+morcS
HEpaK8b76fCFcL5yFsAJkPPfny1IKU+CfaVq60dM/mxbEW6J4mZT/uAiqrCilMC+
FyiATCZur8Ks7p47eZy700DllLod7gWTiuZTgHeQFVoX+jxbCZKlFn5Xspu8ALoK
Mla/q83mICRVy3+eMUsD7DNvoWYpCAYy/oMk0VWfrQ48JkCGbBW2PW/dU2nmqVhY
/11rurkr+1TUvYodnajANtXvUjW1DPOLb4dES4Qc4b7Fw8eFXrARhl5mXiL5HFKR
/VnRshiJ+QwTVkxl+KkZHEm/WS8QD+Zd8leAxh9MCoaU/XrBUBkCAwEAAaNTMFEw
HQYDVR0OBBYEFKUinuD1xRvcNd2Wti/PnBJp7On1MB8GA1UdIwQYMBaAFKUinuD1
xRvcNd2Wti/PnBJp7On1MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD
ggIBAJdJrNBftqkTs2HyuJ3x5RIsTxYh85hJYwNOdFLyzVG6HER9jRCnvmNTjG0O
I5wz5hQvDpwXs4BCCXHQZrTLAi3BEjq3AjrmR/XeGHulbWh3eh8LVu7MiLRgt+Ys
GnL2IaERrbkje24nCCMNPbI3fGDQEhTIYmmX8RJp+5BOJgCycKk6pFgfrjJv2C+d
78pcjlYII6M4vPnr/a08M49Bq6b5ADvIfe5G2KrUvD/+vwoAwv6d/daymHCQ2rY5
kmdVk9VUp3Q4uKoeej4ENJSAUNTV7oTu346oc7q9sJffB5OltqbrE7ichak7lL+v
EjArZHElAhKNFXRZViCMvGDs+7JztqbsfT8Xb6Z27e+WyudB2bOUGm3hKuTIl06D
bA7yUskwEhmkd1CJqO5RLEJjKitOqe6Ye0/GsmPQNDK8GvyXTyGQK5OqBuzEexF0
mlPoIhpSVH3K9SkRTTHvvcbdYlaQLi6gKq2uhbk4PnS2nfBtXqYIy9mxcgBJzLiB
/ydfLcf3GClwgvO1JHp6qAl4CO7oe8jqHpoGuznwi1aqkTyNkQWh0OXq3MS+dyqB
2yXFCFIeKCx18TE1OtuTD3ppBDjpyd0o/a6kYR3FDmdks/J33bGwLsLH3lbN6VjF
PNfNkaE1tfkpSGYsuT1DPxX8aAT4JLUfZ1Si6iO+E0Sj9LXA
-----END CERTIFICATE-----`
	client_crt = `-----BEGIN CERTIFICATE-----
MIID/jCCAeYCAQEwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV
BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDAeFw0xODAyMTMyMDU0MjZaFw0xOTAyMTMyMDU0MjZaMEUxCzAJBgNVBAYTAkFV
MRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRz
IFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD1li7/35Q
C/T6FACSbsd0WlImu42i6w96wfngAfEgbz5Ip+IA2rJ8G5LNHTYYCpr9LlmhY6zm
soHgAkff6XwUnZaetX01UmGP4CD4D3UumkR1uKY4bCSNImm53SZgelOznpsqAWKE
zosMrDcOAJKJSN411KwVzWysfRCPyxvmLETzU9KHFCJ1oY3t1HzYIAqpHv9sMSst
dNHW3X7bWEAVKCQMKO+rWe/wAhE4iTVdlRi02oRoRWSVj41+nk6jI8KJNq70stHc
QSST0A7SUacPYKJWqJRhP1pZ6k4G3ZVE8332az7jvcN1uGGjERZoUbZxGB+mbMCC
GJwnwnNiI6/hAgMBAAEwDQYJKoZIhvcNAQELBQADggIBADNr6QMl57CdHEzNwc2M
CSZsuOLakp8YiovVDOXJ/p/lykUIIcR1rI1iNfb8oOFTZmrndGZVAh76EExdMHYG
m+4Vr2+z/73AZwvhhnLhftOKFFwkdjCfXouPlkc/zmhOORakIFGlLZFkuZRY6k2D
Q8uIt7E5uXSVl11A1LxN5X8lhK2G4lxJZuj1AqEFj9QD44Qy+MdgX38lzGCEXd8c
Y5K8zLJGbgXgYaFxqd0bImfjgjj82+Mui0OTV5PcRlczJX08ygKjcoAMVyvPHu72
3zzxvoNcqUrvbptVvg9c7FSOpK95YZOe1LiyqZCwNJQl4fPRE++XQ4zDNdyiAp76
a6BQg/M8gOpV/VBMTsNDr/yP/7eBqkfvU7jLfz7wKMDdcjeZnKom42f+/XOLEo6E
hyDuHGdQh10bZD/Ukcs69+pA3ioic1A8pQzAElH3IuDBsMJg30x8tACLKNcUY8BE
2eJgrCxWcvq88DeAT03W9AVpFZA8ZQUR3SHCquMBFogsmUDDMN+CoC0u5dBwHP+O
9rmWOXn8gp/zBCKGwemgVV5vSNzJs7z3aoqIiAABl56LBaXxjKzRmXoB/SyUW5zl
1zy4SQTE6SJYqqU6h2yRdT8n0oWN3AMy0VxbJTRq32kdYJVQK9cLKVqpxtCCtPnN
3lV+HDsj7k+AJjHiu1F4O+sp
-----END CERTIFICATE-----`
	client_key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAw9ZYu/9+UAv0+hQAkm7HdFpSJruNousPesH54AHxIG8+SKfi
ANqyfBuSzR02GAqa/S5ZoWOs5rKB4AJH3+l8FJ2WnrV9NVJhj+Ag+A91LppEdbim
OGwkjSJpud0mYHpTs56bKgFihM6LDKw3DgCSiUjeNdSsFc1srH0Qj8sb5ixE81PS
hxQidaGN7dR82CAKqR7/bDErLXTR1t1+21hAFSgkDCjvq1nv8AIROIk1XZUYtNqE
aEVklY+Nfp5OoyPCiTau9LLR3EEkk9AO0lGnD2CiVqiUYT9aWepOBt2VRPN99ms+
473DdbhhoxEWaFG2cRgfpmzAghicJ8JzYiOv4QIDAQABAoIBADKcbZhAYjt7q5cJ
nlA5svA9+2cpJ2SITRrTkKk0t0VDmpwaTw0bd+8dDSZXO0ihTQbLeLx9zwxb67ah
wEN8yuVlCK0BiFdEcBRHvx18mTMvCSxHSSXhxNx4nUw8fBOI6aLNBZqoevaJjmP7
CctjmHtESrEswkBsM36sX6BZxF8Kc4Q5Znuxqksnl6HNoxnjhmygJmYCFTToiTHa
f2HWKBiZfgfxX7WEuHer3h6nmBbBCOX1/hcipBMBBVIqFl1ZSIF/B3lR8UV4/X+a
SNMqggOqkEIuHKkSCKo1lNxEPP2p54EHrKkjepoqMzIFuYnn4qWesMznpmy+zBGB
6PCjfzUCgYEA92etvRVQjBx8dHTSiyCNbS1ELgiCkzar8PGH+ytTIaj/TTF1LfAi
UYRp5MtOKmQXxE3IRLDF8P8rEKC06aV12hVwhd2xfHjje+KZkwWZ2PIj+GbK7f1r
MvKN5eE0NhGiSvu5SiFuks/SV8Qc4StFPmiWf33XKvJuAWNkCu+bUZsCgYEAyqQL
nVNKTlgHNKDJKMHi/buZt8wtwGGXCxcv+w88PmEC0OCbH/V2niCPLvFmK1xDXpru
k7z9FTc+QeasEMtxY/Gcs3IgUzxOHxAL7cn6KBM44uDhpIcv3BFWtR053acVU6S4
IKuijWIJNJEk2qksgQTX7Mv/xq2uXvfZqajdKjMCgYEA3x+5F9s+Pm5+a4TkUSc1
hS4a3C0+ncfjv7QEwCftnGDOhu7A0IJOYRg7bGVShHaq3JaNtC19BwEJ9MALCOD5
bYqCZahvpmNcPeE6Qdb+TiLq/96sy4AOiu8nvBejv9Ode2SUUd/e2jbla9Ppe8VL
eKJYgHicchYb0dKyag54FFsCgYEAuToEB9W3aS9bvsZtuZyooSfXFcND2sMZrqCO
Uh2WAqroSQfVo/vaZiX623z62A2o4xQZmd+5MqhhdxmkFGHyDtouU3SxiYPpIMmp
Lb1etT0E1ZWbi6mqnK0YpcrGNw5gFynMyMg6eKOxKGS33EuhC3ni6Wd7MB9X8ST6
x/M73jMCgYBBge3/ugnZPE78TDL3DdefrjeYFaKhVc622eimS/MEPbkbdxh8azTM
LAoibwDU1NC8/3MfOBYMe6Qklu3kjexOJrfdo0Z7Khgd9F8A4tKwslUndSSlAfKF
2rjfqabVMZMLZ2XEbA4W5JTfaZS4YYGcrjY7+i7OsnSxoYG2sb+xlQ==
-----END RSA PRIVATE KEY-----`
)
