package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/bifurcation/mint"
)

func main() {
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return mint.Dial(network, addr, nil)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := resp.Write(os.Stdout); err != nil {
		log.Fatal(err)
	}

	// Resumption
	resp, err = client.Get("https://" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := resp.Write(os.Stdout); err != nil {
		log.Fatal(err)
	}
}
