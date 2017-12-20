package tls

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"

	"golang_org/x/crypto/ed25519"
)

func TestEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{}
	template.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)

	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.MaxVersion = VersionTLS13
	config.Certificates = []Certificate{
		Certificate{
			Certificate: [][]byte{cert},
			PrivateKey:  priv,
		},
	}

	ln := newLocalListener(t)
	defer ln.Close()

	server := func() error {
		sconn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		defer sconn.Close()

		srv := Server(sconn, config)
		if err := srv.Handshake(); err != nil {
			t.Log("server handshake error:", err)
			return fmt.Errorf("handshake: %v", err)
		}
		return srv.Close()
	}

	errChan := make(chan error, 1)
	go func() { errChan <- server() }()

	conn, err := Dial("tcp", ln.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		conn.Close()
		t.Fatal(err)
	}

	if _, err := conn.Write([]byte("Hello, World!")); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	conn.Close()

	if err := <-errChan; err != nil {
		t.Fatal(err)
	}
}
