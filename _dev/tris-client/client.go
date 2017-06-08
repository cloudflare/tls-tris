package main

import (
	"net/http"
	"crypto/tls"
	"os"
	"fmt"
)

func main() {
	var hostname string
	switch len(os.Args) {
	case 2:
		hostname = os.Args[1]
	default:
		panic("Usage: ./client hostname")
	}

	config := &tls.Config{
		MaxVersion: tls.VersionTLS13Draft18,
		//MaxVersion: tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	trans := &http.Transport{TLSClientConfig: config}

	client := &http.Client{Transport: trans}
	resp, err := client.Get(hostname)
	if err != nil {
		panic(err)
	}
	
	fmt.Println("RESPONSE:")
	fmt.Printf("%v", resp)
}
