// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

// A PEM-encoded "delegation certificate", an X.509 certificate with the
// DelegationUsage extension. The extension is defined in
// specified in https://tools.ietf.org/html/draft-ietf-tls-subcerts-02.
var dcDelegationCertPEM = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIQXXtl0v50W2OadoW0QwLUlzAKBggqhkjOPQQDAjAUMRIw
EAYDVQQKEwlBY21lIEluYy4wHhcNMTgwNzMwMjAxMTE5WhcNMTgwODA2MjAxMTE5
WjAUMRIwEAYDVQQKEwlBY21lIEluYy4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATcQuuaUNJ3kqKGs4DBdJVd7zWzyGANT4uBNGVkZ2cgaDsdFnx99fGibfgoWer8
HLt9Z+S6Hs+8bDPBHNgTR/Lfo1UwUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwR/AAABMA0GCSsG
AQQBgtpLLAQAMAoGCCqGSM49BAMCA0cAMEQCIEMdIkwwmzQAJ6RSDT3wcrsySx2B
5Lvx5HGzc43Fgu9eAiAi4sFXnizFBVUL43qXZBq4ARw17o0JW3/7eec1xttQhw==
-----END CERTIFICATE-----
`

// The PEM-encoded "delegation key", the secret key associated with the
// delegation certificate. This is a key for ECDSA with P256 and SHA256.
var dcDelegationKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAS/pGktmxK1hlt3gF4N2nkMrJnoZihvOO63nnNcxXQroAoGCCqGSM49
AwEHoUQDQgAE3ELrmlDSd5KihrOAwXSVXe81s8hgDU+LgTRlZGdnIGg7HRZ8ffXx
om34KFnq/By7fWfkuh7PvGwzwRzYE0fy3w==
-----END EC PRIVATE KEY-----
`

// A certificate without the DelegationUsage extension.
var dcCertPEM = `-----BEGIN CERTIFICATE-----
MIIBajCCAQ+gAwIBAgIRAMUg/VFqJaWWJwZ9iHoMjqIwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0xODA3MzAyMDExMTlaFw0xOTA3MzAyMDExMTla
MBIxEDAOBgNVBAoTB0FjbWUgQ28wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA
n+oeWSvSNHhEskSRgkkerCQDoV/NA+r3S5AtCOFT5AYLt8xltSTWerFI/YlZLIcL
xlJPT7T+XpBnfS6xaAuxo0YwRDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49
BAMCA0kAMEYCIQCFGWnoJmwH1rxNCKBJWVDBKDTSsYhySRk4h9RPyR8bUwIhAJxc
KFyrowMTan791RJnyANH/4uYhmvkfhfrFGSTXUli
-----END CERTIFICATE-----
`

// The secret key associatted with dcCertPEM.
var dcKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEP82pOhzx0tKkky9t0OmUo9MHgmfdAHxDN2cHmWGqOhoAoGCCqGSM49
AwEHoUQDQgAEwJ/qHlkr0jR4RLJEkYJJHqwkA6FfzQPq90uQLQjhU+QGC7fMZbUk
1nqxSP2JWSyHC8ZST0+0/l6QZ30usWgLsQ==
-----END EC PRIVATE KEY-----
`

// dcTestDC stores delegated credentials and their secret keys.
type dcTestDC struct {
	Name       string
	Version    int
	Scheme     int
	DC         []byte
	PrivateKey []byte
}

// Test data used for testing the TLS handshake with the delegated creedential
// extension. The PEM block encodes a DER encoded slice of dcTestDC's.
var dcTestDCsPEM = `-----BEGIN DC TEST DATA-----
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
-----END DC TEST DATA-----
`

var dcTestDCs []dcTestDC
var dcTestConfig *Config
var dcTestDelegationCert Certificate
var dcTestCert Certificate
var dcTestNow time.Time

func init() {
	// Parse the PEM block containing the test DCs.
	block, _ := pem.Decode([]byte(dcTestDCsPEM))
	if block == nil {
		panic("failed to decode DC tests PEM block")
	}

	// Parse the DER-encoded test DCs.
	_, err := asn1.Unmarshal(block.Bytes, &dcTestDCs)
	if err != nil {
		panic("failed to unmarshal DC test ASN.1 data")
	}

	// The base configuration for the client and server.
	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcTestNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS10,
		MaxVersion:   VersionTLS13,
		CipherSuites: allCipherSuites(),
	}

	// The delegation certificate.
	dcTestDelegationCert, err = X509KeyPair([]byte(dcDelegationCertPEM), []byte(dcDelegationKeyPEM))
	if err != nil {
		panic(err)
	}
	dcTestDelegationCert.Leaf, err = x509.ParseCertificate(dcTestDelegationCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// A certificate without the the DelegationUsage extension for X.509.
	dcTestCert, err = X509KeyPair([]byte(dcCertPEM), []byte(dcKeyPEM))
	if err != nil {
		panic(err)
	}
	dcTestCert.Leaf, err = x509.ParseCertificate(dcTestCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// For testing purposes, use the point at which the test DCs were generated
	// as the current time.  This is the same as the time at which the
	// delegation certificate was generated.
	dcTestNow = dcTestDelegationCert.Leaf.NotBefore

	// Make these roots of these certificates the client's trusted CAs.
	dcTestConfig.RootCAs = x509.NewCertPool()

	raw := dcTestDelegationCert.Certificate[len(dcTestDelegationCert.Certificate)-1]
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(root)

	raw = dcTestCert.Certificate[len(dcTestCert.Certificate)-1]
	root, err = x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(root)
}

// Executes the handshake with the given configuration and returns true if the
// delegated credential extension was successfully negotiated.
func testConnWithDC(t *testing.T, clientConfig, serverConfig *Config) (bool, error) {
	ln := newLocalListener(t)
	defer ln.Close()

	// Listen for and serve a single client connection.
	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		srv := Server(sconn, serverConfig)
		if err := srv.Handshake(); err != nil {
			serr = fmt.Errorf("handshake: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	// Dial the server.
	cli, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, err
	}
	defer cli.Close()

	srv := <-srvCh
	if srv == nil {
		return false, serr
	}

	// Return true if the client's conn.dc structure was instantiated.
	st := cli.ConnectionState()
	return (st.DelegatedCredential != nil), nil
}

// Checks that the client suppports a version >= 1.2 and accepts delegated
// credentials. If so, it returns the delegation certificate; otherwise it
// returns a plain certificate.
func testServerGetCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS12))
	}

	if versOk && ch.AcceptsDelegatedCredential {
		return &dcTestDelegationCert, nil
	}
	return &dcTestCert, nil
}

// Various test cases for handshakes involving DCs.
var dcTesters = []struct {
	clientDC         bool
	serverDC         bool
	clientSkipVerify bool
	clientMaxVers    uint16
	serverMaxVers    uint16
	nowOffset        time.Duration
	dcTestName       string
	expectSuccess    bool
	expectDC         bool
	name             string
}{
	{true, true, false, VersionTLS13, VersionTLS13, 0, "tls13p256", true, true, "tls13"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "tls13p521", true, true, "tls13"},
	{true, false, false, VersionTLS13, VersionTLS13, 0, "tls13p256", true, false, "server no dc"},
	{true, true, false, VersionTLS12, VersionTLS13, 0, "tls13p256", true, false, "client old"},
	{true, true, false, VersionTLS13, VersionTLS12, 0, "tls13p256", true, false, "server old"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "badkey", false, false, "bad key"},
	{true, true, true, VersionTLS13, VersionTLS13, 0, "badsig", true, true, "bad key, skip verify"},
	{true, true, false, VersionTLS13, VersionTLS13, dcMaxTTL, "tls13", false, false, "expired dc"},
	{true, true, false, VersionTLS13, VersionTLS13, 0, "badvers", false, false, "dc wrong version"},
	{true, true, false, VersionTLS12, VersionTLS12, 0, "tls12", true, false, "tls12"},
}

// Tests the handshake with the delegated credential extension for each test
// case in dcTests.
func TestDCHandshake(t *testing.T) {
	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetCertificate

	for i, tester := range dcTesters {
		clientConfig.MaxVersion = tester.clientMaxVers
		serverConfig.MaxVersion = tester.serverMaxVers
		clientConfig.InsecureSkipVerify = tester.clientSkipVerify
		clientConfig.AcceptDelegatedCredential = tester.clientDC
		clientConfig.Time = func() time.Time {
			return dcTestNow.Add(time.Duration(tester.nowOffset))
		}

		if tester.serverDC {
			serverConfig.GetDelegatedCredential = func(
				ch *ClientHelloInfo, vers uint16) ([]byte, crypto.PrivateKey, error) {
				if vers < VersionTLS13 {
					return nil, nil, nil
				}
				for _, test := range dcTestDCs {
					if test.Name == tester.dcTestName {
						sk, err := x509.ParseECPrivateKey(test.PrivateKey)
						if err != nil {
							return nil, nil, err
						}
						return test.DC, sk, nil
					}
				}
				return nil, nil, fmt.Errorf("Test DC with name '%s' not found", tester.dcTestName)
			}
		} else {
			serverConfig.GetDelegatedCredential = nil
		}

		usedDC, err := testConnWithDC(t, clientConfig, serverConfig)
		if err != nil && tester.expectSuccess {
			t.Errorf("test #%d (%s) fails: %s", i+1, tester.name, err)
		} else if err == nil && !tester.expectSuccess {
			t.Errorf("test #%d (%s) succeeds; expected failure", i+1, tester.name)
		}

		if usedDC != tester.expectDC {
			t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, tester.name, usedDC, tester.expectDC)
		}
	}
}
