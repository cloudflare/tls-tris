package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10:        "1.0",
	tls.VersionTLS11:        "1.1",
	tls.VersionTLS12:        "1.2",
	tls.VersionTLS13:        "1.3",
	tls.VersionTLS13Draft18: "1.3 (draft 18)",
}

func startServer(addr string, rsa, offer0RTT, accept0RTT bool) {
	cert, err := tls.X509KeyPair([]byte(ecdsaCert), []byte(ecdsaKey))
	if rsa {
		cert, err = tls.X509KeyPair([]byte(rsaCert), []byte(rsaKey))
	}
	if err != nil {
		log.Fatal(err)
	}
	var Max0RTTDataSize uint32
	if offer0RTT {
		Max0RTTDataSize = 100 * 1024
	}
	allowShortHeaders := os.Getenv("TLSTRIS_SHORT_HEADERS")
	
	s := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			Certificates:    []tls.Certificate{cert},
			Max0RTTDataSize: Max0RTTDataSize,
			Accept0RTTData:  accept0RTT,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				// If we send the first flight too fast, NSS sends empty early data.
				time.Sleep(500 * time.Millisecond)
				return nil, nil
			},
			AllowShortHeaders: allowShortHeaders == "true",
		},
	}
	log.Fatal(s.ListenAndServeTLS("", ""))
}

var confirmingAddr string

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tlsConn := r.Context().Value(http.TLSConnContextKey).(*tls.Conn)
		server := r.Context().Value(http.ServerContextKey).(*http.Server)

		with0RTT := ""
		if !tlsConn.ConnectionState().HandshakeConfirmed {
			with0RTT = " [0-RTT]"
		}
		if server.Addr == confirmingAddr || r.URL.Path == "/confirm" {
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

	switch len(os.Args) {
	case 2:
		startServer(os.Args[1], true, true, true)
	case 6:
		confirmingAddr = os.Args[5]
		go startServer(os.Args[1], false, false, false) // first port: ECDSA (and no 0-RTT)
		go startServer(os.Args[2], true, false, true)   // second port: RSA (and accept 0-RTT but not offer it)
		go startServer(os.Args[3], false, true, false)  // third port: offer and reject 0-RTT
		go startServer(os.Args[4], false, true, true)   // fourth port: offer and accept 0-RTT
		startServer(os.Args[5], false, true, true)      // fifth port: offer and accept 0-RTT but confirm
	}
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
