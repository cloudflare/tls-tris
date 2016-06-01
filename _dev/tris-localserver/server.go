package main

import (
	"log"
	"net/http"
	"os"

	"github.com/FiloSottile/tls-tris"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir(".")))

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	l, err := tls.Listen("tcp", os.Args[1], &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	s := &http.Server{}
	log.Println(s.Serve(l))
}
