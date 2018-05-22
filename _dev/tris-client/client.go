package main

import (
//	"net/http"
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
		MaxVersion: tls.VersionTLS13Draft23,
		CurvePreferences: []tls.CurveID{tls.SIDHP751AndX25519},
		InsecureSkipVerify: true,
	}


	con, err := tls.Dial("tcp", hostname, config)
	if err != nil {
		fmt.Println("ERROR")
	}
	fmt.Printf("TLS VERSION: %X\n", con.ConnectionState().Version)
}
