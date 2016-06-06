package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir(".")))

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	l, err := tls.Listen("tcp", os.Args[1], tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	s := &http.Server{
		TLSConfig: tlsConfig,
	}
	log.Println(s.Serve(l))
}
