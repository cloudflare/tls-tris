package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"./boringssl/ssl/test/runner"
)

func main() {
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return runner.Dial(network, addr, &runner.Config{
				InsecureSkipVerify: true,
			})
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := resp.Write(os.Stdout); err != nil {
		log.Fatal(err)
	}
}
