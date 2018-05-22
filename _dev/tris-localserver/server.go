package main

import (
	"crypto/tls"
	"flag"
	"net/http"
    "io/ioutil"
    "strings"
)

type server struct {
	Address             string
    PubKeyFile          string
    PrvKeyFile          string
}

func sayHello(w http.ResponseWriter, r *http.Request) {
  message := r.URL.Path
  message = strings.TrimPrefix(message, "/")
  message = "Hello " + message
  // checks if I'm using correct version of tls
  _ = tls.VersionTLS13Draft23

  w.Write([]byte(message))
}

func (s *server) start() {

    pubkey, err := ioutil.ReadFile(s.PubKeyFile); if err != nil {
        panic(err)
    }
    prvkey, err := ioutil.ReadFile(s.PrvKeyFile); if err != nil {
        panic(err)
    }
    cert, err := tls.X509KeyPair(pubkey, prvkey); if err != nil {
        panic(err)
    }

	httpServer := &http.Server{
		Addr: s.Address,
		TLSConfig: &tls.Config{
            //MaxVersion: tls.VersionTLS13Draft23,
            //MinVersion: tls.VersionTLS13Draft23,
            CurvePreferences: []tls.CurveID{tls.SIDHP751AndX25519, tls.X25519, tls.CurveP256},
			Certificates:    []tls.Certificate{cert},
		},
	}

	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
        panic(err)
    }
}

func main() {
    arg_addr := flag.String("b" , "0.0.0.0:4443",  "Address:port used for binding")
    pub_key  := flag.String("p" , "certs/fullchain.pem",  "Public key")
    prv_key  := flag.String("r" , "certs/privkey.pem", "Private key")
    flag.Parse()

    http.HandleFunc("/", sayHello)

    s := new(server)
    s.Address=*arg_addr
    s.PubKeyFile =*pub_key
    s.PrvKeyFile =*prv_key
	s.start()
}

