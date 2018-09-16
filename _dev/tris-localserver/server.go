package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ZeroRTT_t int
type PubKeyAlgo_t int

// Bitset
const (
	ZeroRTT_None   ZeroRTT_t = 0
	ZeroRTT_Offer            = 1 << 0
	ZeroRTT_Accept           = 1 << 1
)

type server struct {
	Address string
	ZeroRTT ZeroRTT_t
	TLS     tls.Config
}

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

func NewServer() *server {
	s := new(server)
	s.ZeroRTT = ZeroRTT_None
	s.Address = "0.0.0.0:443"
	s.TLS = tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			// If we send the first flight too fast, NSS sends empty early data.
			time.Sleep(500 * time.Millisecond)
			return nil, nil
		},
		MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
	}

	return s
}

func (s *server) start() {
	var err error
	if (s.ZeroRTT & ZeroRTT_Offer) == ZeroRTT_Offer {
		s.TLS.Max0RTTDataSize = 100 * 1024
	}

	if keyLogFile := os.Getenv("SSLKEYLOGFILE"); keyLogFile != "" {
		s.TLS.KeyLogWriter, err = os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		log.Println("Enabled keylog")
	}

	s.TLS.ClientCAs = x509.NewCertPool()
	s.TLS.ClientCAs.AppendCertsFromPEM([]byte(rsaCa_client))
	s.TLS.Accept0RTTData = ((s.ZeroRTT & ZeroRTT_Accept) == ZeroRTT_Accept)
	s.TLS.NextProtos = []string{"npn_proto"}

	httpServer := &http.Server{
		Addr:      s.Address,
		TLSConfig: &s.TLS,
	}
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}

func enableQR(s *server) {
	var defaultCurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	var sidhCurves = []tls.CurveID{tls.SidhP751Curve25519, tls.SidhP751Curve448, tls.SidhP503Curve25519}
	s.TLS.CurvePreferences = append(defaultCurvePreferences, sidhCurves...)
}

// setServerCertificateFromArgs sets server certificate from an argument provided by the caller. Possible values
// for arg_cert:
// * "rsa": sets hardcoded RSA keypair
// * "ecdsa": sets hardcoded ECDSA keypair
// * FILE1:FILE2: Uses private key from FILE1 and public key from FILE2. Both must be in PEM format. FILE2 can
//   be single certificate or certificate chain.
// * nil: fallbacks to "rsa"
//
// Function generate a panic in case certificate can't be correctly set
func (s *server) setServerCertificateFromArgs(arg_cert *string) {
	var certStr, keyStr []byte
	var cert tls.Certificate
	var err error

	if arg_cert == nil {
		// set rsa by default
		certStr, keyStr = []byte(rsaCert), []byte(rsaKey)
	} else {
		switch *arg_cert {
		case "rsa":
			certStr, keyStr = []byte(rsaCert), []byte(rsaKey)
		case "ecdsa":
			certStr, keyStr = []byte(ecdsaCert), []byte(ecdsaKey)
		default:
			files := strings.Split(*arg_cert, ":")
			if len(files) != 2 {
				err = errors.New("Wrong format provided after -cert.")
				goto err
			}
			keyStr, err = ioutil.ReadFile(files[0])
			if err != nil {
				goto err
			}
			certStr, err = ioutil.ReadFile(files[1])
			if err != nil {
				goto err
			}
		}
	}

	cert, err = tls.X509KeyPair(certStr, keyStr)
	if err != nil {
		goto err
	}

	s.TLS.Certificates = []tls.Certificate{cert}
err:
	if err != nil {
		// Not possible to proceed really
		log.Fatal(err)
		panic(err)
	}
}

func main() {

	s := NewServer()

	arg_addr := flag.String("b", "0.0.0.0:443", "Address:port used for binding")
	arg_cert := flag.String("cert", "rsa", "Public algorithm to use:\nOptions [rsa, ecdsa, PrivateKeyFile:CertificateChainFile]")
	arg_zerortt := flag.String("rtt0", "n", `0-RTT, accepts following values [n: None, a: Accept, o: Offer, oa: Offer and Accept]`)
	arg_confirm := flag.Bool("rtt0ack", false, "0-RTT confirm")
	arg_clientauth := flag.Bool("cliauth", false, "Performs client authentication (RequireAndVerifyClientCert used)")
	arg_qr := flag.Bool("qr", false, "Enable quantum-resistant algorithms")
	flag.Parse()

	s.Address = *arg_addr

	s.setServerCertificateFromArgs(arg_cert)

	if *arg_zerortt == "a" {
		s.ZeroRTT = ZeroRTT_Accept
	} else if *arg_zerortt == "o" {
		s.ZeroRTT = ZeroRTT_Offer
	} else if *arg_zerortt == "oa" {
		s.ZeroRTT = ZeroRTT_Offer | ZeroRTT_Accept
	}

	if *arg_clientauth {
		s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if *arg_qr {
		enableQR(s)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tlsConn := r.Context().Value(http.TLSConnContextKey).(*tls.Conn)

		with0RTT := ""
		if !tlsConn.ConnectionState().HandshakeConfirmed {
			with0RTT = " [0-RTT]"
		}
		if *arg_confirm || r.URL.Path == "/confirm" {
			if err := tlsConn.ConfirmHandshake(); err != nil {
				log.Fatal(err)
			}
			if with0RTT != "" {
				with0RTT = " [0-RTT confirmed]"
			}
			if !tlsConn.ConnectionState().HandshakeConfirmed {
				panic("HandshakeConfirmed false after ConfirmHandshake")
			}
		}

		resumed := ""
		if r.TLS.DidResume {
			resumed = " [resumed]"
		}

		http2 := ""
		if r.ProtoMajor == 2 {
			http2 = " [HTTP/2]"
		}

		fmt.Fprintf(w, "<!DOCTYPE html><p>Hello TLS %s%s%s%s _o/\n", tlsVersionToName[r.TLS.Version], resumed, with0RTT, http2)
	})

	http.HandleFunc("/ch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Client Hello packet (%d bytes):\n%s", len(r.TLS.ClientHello), hex.Dump(r.TLS.ClientHello))
	})

	s.start()
}

const (
	rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1DHcIM3SThFqy8nAkPQFX0E7ph8jqh8EATXryjKHGuVjR3Xh
OQ0BSPoJxyfdg/VEwevFrtmZAfz0WCbxvP2SVCmf7oobg4V2KPSo3nNt9vlBFUne
RtIyHRQ8YRnGSWaRHzJbX6ffltnG2aD+8qUfk161rdZgxBA9G0Ga47IkwQhT2Hqu
H3dW2Uu4W2WMyt6gX/tdyEAV57MOPcoceknr7Nb2kfiuDPR7h6wFrW3I6eoj8oX2
SkIOuVNt1Z31BAUcPJDUjqopI0o9tolM/7X13M8dEY0OJQVr7FQYDF9JeSYeEMyb
wizjBaHDm48mSghP1o5UssQBbNNC83btXCjiLQIDAQABAoIBACzvGgRAUYaCnbDl
2kdXxUN0luMIuQ6vXrO67WF17bI+XRWm2riwDlObzzJDON9Wsua1vLjYD1SickOw
i4RP1grIfbuPt1/UhT8LAC+LFgA0rBmL+OvaWw5ZWKffQ2QLujN3AG5zKB/Tog43
z4UmfldAuQxE11zta2M4M0qAUNQnQj1oiuI8RUdG0VvvLw8Htdi1ogH0CI5R669z
NjHt+JV+2gzKx6EX0s8mQL3yXGkC2xXItRbFclyCMJEhPS7QbBu+tru35N6WpzAq
BCl2Q7LQogvSA6MXuMOx6CyuExVfgmhbfeoheLE8gmXwl0Y37n/g6ZBZFAtpCjcs
UckPv0ECgYEA1orl7RwgIsZljMap6vWtMGoRIHKmT91DGpMmkh4suZe+yAk85maU
49Vd+8ZfIN41AH37yrsGOcPHgz5o5QufELpoub6DCsQ7u9F1vQp55cp+qyBWzAgz
b/xUuVnIyv3kLan3fpk7ZGCBXFBpLG0QXMFOHtda3Mlk5SmuoEYaYRkCgYEA/TLR
u4neKqyqwsqMuRJGC1iKFVmfCjZeNMtPNbTWpdqez/vvT8APnEpIumUGt8YROLGZ
8biUr5/ViOkmaP3wmQbO9m2/cE01lMTYv75w1cw2KVQe6kAHJkOx+JEx9xg53RJ/
QlFtG5MQUy2599Gxp8BMGaXLH5yo4qwvNvY6CDUCgYEArxr7AwX7rKZlZ/sV4HHY
gzVu+R7aY0DibiRATO5X7rrNuhLgI+UCDNqvNLn6FqeGdvpcsmDneeozQwmDL77G
ey7KHyBBcF4tquQQxtRwHX+i1yUz8p+W7AX1WLrRSezjeenJ2QhUE1849hGjZeE2
g546lq2Kub2enfPhVWsiSLECgYEA72T5QCPeVuLioUH5Q5Kvf1K7W+xcnr9A2xHP
Vqwgtre5qFQ/tFuXZuIlWXbjnyY6aiwhrZYjntm0f7pRgrt2nHj/fafOdVPK8Voc
xU4+SSbHntPWVw0qtVcUEjzVzRauvwMaJ43tZ0DpEnwNdO5i1oTObwF+x+jLFWZP
TdwIinECgYBzjZeCxxOMk5SlPpTsLUtgC+q3m1AavXhUVNEPP2gKMOIPTETPbhbG
LBxB2vVbJiS3J7itQy8gceT89O0vSEZnaTPXiM/Ws1QbkBJ8yW7KI7X4WuzN4Imq
/cLBRXLb8R328U27YyQFNGMjr2tX/+vx5FulJjSloWMRNuFWUngv7w==
-----END RSA PRIVATE KEY-----`
	rsaCert = `-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIRANBDimJ/ww2tz77qcYIhuZowDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA5MjQxNzI5MTlaFw0yNjA5MjIxNzI5
MTlaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDUMdwgzdJOEWrLycCQ9AVfQTumHyOqHwQBNevKMoca5WNHdeE5DQFI
+gnHJ92D9UTB68Wu2ZkB/PRYJvG8/ZJUKZ/uihuDhXYo9Kjec232+UEVSd5G0jId
FDxhGcZJZpEfMltfp9+W2cbZoP7ypR+TXrWt1mDEED0bQZrjsiTBCFPYeq4fd1bZ
S7hbZYzK3qBf+13IQBXnsw49yhx6Sevs1vaR+K4M9HuHrAWtbcjp6iPyhfZKQg65
U23VnfUEBRw8kNSOqikjSj22iUz/tfXczx0RjQ4lBWvsVBgMX0l5Jh4QzJvCLOMF
ocObjyZKCE/WjlSyxAFs00Lzdu1cKOItAgMBAAGjSzBJMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAygPV4enmvwSuMd1JarxOXpOK
Z4Nsk7EKlfCPgzxQUOkFdLIr5ZG1kUkQt/omzTmoIWjLAsoYzT0ZCPOrioczKsWj
MceFUIkT0w+eIl+8DzauPy34o8rjcApglF165UG3iphlpI+jdPzv5TBarUAbwsFb
ClMLEiNJQ0OMxAIaRtb2RehD4q3OWlpWf6joJ36PRBqL8T5+f2x6Tg3c64UR+QPX
98UcCQHHdEhm7y2z5Z2Wt0B48tZ+UAxDEoEwMghNyw7wUD79IRlXGYypBnXaMuLX
46aGxbsSQ7Rfg62Co3JG7vo+eJd0AoZHrtFUnfM8V70IFzMBZnSwRslHRJe56Q==
-----END CERTIFICATE-----`
	rsaCa_client = `-----BEGIN CERTIFICATE-----
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
	ecdsaCert = `-----BEGIN CERTIFICATE-----
MIIBbTCCAROgAwIBAgIQZCsHZcs5ZkzV+zC2E6j5RzAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE2MDkyNDE3NTE1OFoXDTI2MDkyMjE3NTE1OFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDTO
B3IyzjYfKCp2HWy+P3QHxhdBT4AUGYgwTiSEj5phumPIahFNcOSWptN0UzlZvJdN
MMjVmrFYK/FjF4abkNKjSzBJMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggq
hkjOPQQDAgNIADBFAiEAp9W157PM1IadPBc33Cbj7vaFvp+rXs/hSuMCzP8pgV8C
IHCswo1qiC0ZjQmWsBlmz5Zbp9rOorIzBYmGRhRdNs3j
-----END CERTIFICATE-----`
	ecdsaKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFdhO7IW5UIwpB1e2Vunm9QyKvUHWcVwGfLjhpOajuR7oAoGCCqGSM49
AwEHoUQDQgAENM4HcjLONh8oKnYdbL4/dAfGF0FPgBQZiDBOJISPmmG6Y8hqEU1w
5Jam03RTOVm8l00wyNWasVgr8WMXhpuQ0g==
-----END EC PRIVATE KEY-----`
)
