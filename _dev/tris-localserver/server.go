package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

func enablePQ(s *server, enableDefault bool) {
	var pqGroups = []tls.CurveID{tls.HybridSIDHp503Curve25519, tls.HybridSIKEp503Curve25519}
	if enableDefault {
		var defaultCurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
		s.TLS.CurvePreferences = append(s.TLS.CurvePreferences, defaultCurvePreferences...)
	}
	s.TLS.CurvePreferences = append(s.TLS.CurvePreferences, pqGroups...)
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
	arg_pq := flag.String("pq", "", "Enable quantum-resistant algorithms [c: Support classical and Quantum-Resistant, q: Enable Quantum-Resistant only]")
	arg_esniKeys := flag.String("esni-keys", "", "File with base64-encoded ESNIKeys")
	arg_esniPrivate := flag.String("esni-private", "", "Private key file for ESNI")
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

	if *arg_pq == "c" {
		enablePQ(s, true)
	} else if *arg_pq == "q" {
		enablePQ(s, false)
	}

	var err error
	var esniKeys *tls.ESNIKeys
	var esniPrivateKey []byte
	if *arg_esniPrivate == "" && *arg_esniKeys != "" ||
		*arg_esniPrivate != "" && *arg_esniKeys == "" {
		log.Fatal("Both -esni-keys and -esni-private must be provided.")
	}
	if *arg_esniPrivate != "" {
		esniPrivateKey, err = ioutil.ReadFile(*arg_esniPrivate)
		if err != nil {
			log.Fatalf("Failed to read ESNI private key: %s", err)
		}
	}
	if *arg_esniKeys != "" {
		contents, err := ioutil.ReadFile(*arg_esniKeys)
		if err != nil {
			log.Fatalf("Failed to read ESNIKeys: %s", err)
		}
		esniKeysBytes, err := base64.StdEncoding.DecodeString(string(contents))
		if err != nil {
			log.Fatal("Bad -esni-keys: %s", err)
		}
		esniKeys, err = tls.ParseESNIKeys(esniKeysBytes)
		if esniKeys == nil {
			log.Fatalf("Cannot parse ESNIKeys: %s", err)
		}
		s.TLS.GetServerESNIKeys = func([]byte) (*tls.ESNIKeys, []byte, error) { return esniKeys, esniPrivateKey, nil }
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
