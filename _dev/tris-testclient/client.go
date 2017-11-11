package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var tlsVersionToName = map[uint16]string{
	tls.VersionTLS10:        "1.0",
	tls.VersionTLS11:        "1.1",
	tls.VersionTLS12:        "1.2",
	tls.VersionTLS13:        "1.3",
	tls.VersionTLS13Draft18: "1.3 (draft 18)",
	tls.VersionTLS13Draft21: "1.3 (draft 21)",
}

var cipherSuiteIdToName = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

type Client struct {
	KeyLogWriter io.Writer
	failed       uint
}

func (c *Client) run(addr string, version, cipherSuite uint16) {
	fmt.Printf("TLS %s with %s\n", tlsVersionToName[version], cipherSuiteIdToName[cipherSuite])
	tls_config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       []uint16{cipherSuite},
		KeyLogWriter:       c.KeyLogWriter,
	}
	con, err := tls.Dial("tcp", addr, tls_config)
	if err != nil {
		fmt.Printf("handshake failed: %v\n\n", err)
		c.failed++
		return
	}
	defer con.Close()

	_, err = con.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		fmt.Printf("Write failed: %v\n\n", err)
		c.failed++
		return
	}

	buf := make([]byte, 1024)
	n, err := con.Read(buf)
	if err != nil {
		fmt.Printf("Read failed: %v\n\n", err)
		c.failed++
		return
	}
	fmt.Printf("Read %d bytes\n", n)

	fmt.Println("OK\n")
}

func main() {
	var keylog_file string
	var enable_rsa, enable_ecdsa bool
	flag.StringVar(&keylog_file, "keylogfile", "", "Secrets will be logged here")
	flag.BoolVar(&enable_rsa, "rsa", true, "Whether to enable RSA cipher suites")
	flag.BoolVar(&enable_ecdsa, "ecdsa", true, "Whether to enable ECDSA cipher suites")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	addr := flag.Arg(0)
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	client := Client{}
	if keylog_file == "" {
		keylog_file = os.Getenv("SSLKEYLOGFILE")
	}
	if keylog_file != "" {
		keylog_writer, err := os.OpenFile(keylog_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		client.KeyLogWriter = keylog_writer
		log.Println("Enabled keylog")
	}

	if enable_rsa {
		// Sanity check: TLS 1.2 with the mandatory cipher suite from RFC 5246
		client.run(addr, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	}
	if enable_ecdsa {
		// Sane cipher suite for TLS 1.2 with an ECDSA cert (as used by boringssl)
		client.run(addr, tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	}

	client.run(addr, tls.VersionTLS13, tls.TLS_CHACHA20_POLY1305_SHA256)
	client.run(addr, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	client.run(addr, tls.VersionTLS13, tls.TLS_AES_256_GCM_SHA384)

	// TODO test with client cert
	// TODO test other kex methods besides X25519, like MTI secp256r1
	// TODO limit supported groups?

	if client.failed > 0 {
		log.Fatalf("Failed handshakes: %d\n", client.failed)
	} else {
		fmt.Println("All handshakes passed")
	}
}
