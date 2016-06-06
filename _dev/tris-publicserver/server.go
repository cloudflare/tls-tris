package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"rsc.io/letsencrypt"
)

func main() {
	var (
		hostname = flag.String("h", "", "the hostname to obtain a certificate for")
		target   = flag.String("t", "", "the target to reverse proxy to")
		email    = flag.String("e", "", "the email to register to Let's Encrypt")
	)
	flag.Parse()
	if *hostname == "" || *target == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -h tls13.example.com -t https://blog.example.com [-e me@example.com]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var m letsencrypt.Manager
	m.SetHosts([]string{*hostname})
	if *email != "" {
		if err := m.Register(*email, func(string) bool { return true }); err != nil {
			log.Fatal(err)
		}
	}
	if err := m.CacheFile("letsencrypt.cache"); err != nil {
		log.Fatal(err)
	}

	l, err := tls.Listen("tcp", ":https", &tls.Config{
		MinVersion:     tls.VersionTLS10,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	s := &http.Server{}
	http.Handle("/", NewReverseProxy(*target))
	log.Println(s.Serve(l))
}

func NewReverseProxy(target string) *httputil.ReverseProxy {
	t, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	director := func(req *http.Request) {
		req.URL.Scheme = t.Scheme
		req.URL.Host = t.Host
		req.Host = t.Host

	}
	return &httputil.ReverseProxy{Director: director}
}
