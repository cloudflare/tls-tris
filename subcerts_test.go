// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"
)

// A PEM-encoded "delegation certificate", an X.509 certificate with the
// DelegationUsage extension. The extension is defined in
// specified in https://tools.ietf.org/html/draft-ietf-tls-subcerts-03.
const DcCertWithDelegationUsage = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIQFPrGWi6iIFqO9Vm/7VKk6jAKBggqhkjOPQQDAjAUMRIw
EAYDVQQKEwlBY21lIEluYy4wHhcNMTkwODE0MjMwNzEyWhcNMTkwODIxMjMwNzEy
WjAUMRIwEAYDVQQKEwlBY21lIEluYy4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASbTU38xZke+7nv0mnFKGSDa4EBkNkTiwig4RgPjlzLVSSJJQna0jhqAju7eeS/
FCegeunOC9RBeeFHcbK3SMOEo1UwUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwR/AAABMA0GCSsG
AQQBgtpLLAQAMAoGCCqGSM49BAMCA0cAMEQCIGSkHJFqDL/uFchUJV++4SGKxxAf
t1gmce6yX6kKYg+ZAiAGLDwy1tImngiY3OBVpjL49vGfsYJ7vpRkPmApuL55qQ==
-----END CERTIFICATE-----`

// The PEM-encoded "delegation key", the secret key associated with the
// delegation certificate. This is a key for ECDSA with P256 and SHA256.
const DcKeyWithDelegationUsage = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMKB8JN8diRY5LTAfPxaLbdfV2SacUIq9TE110dPwXgjoAoGCCqGSM49
AwEHoUQDQgAEm01N/MWZHvu579JpxShkg2uBAZDZE4sIoOEYD45cy1UkiSUJ2tI4
agI7u3nkvxQnoHrpzgvUQXnhR3Gyt0jDhA==
-----END EC PRIVATE KEY-----`

// A certificate without the DelegationUsage extension.
const DcCertWithoutDelegationUsage = `-----BEGIN CERTIFICATE-----
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

// The secret key associatted with DcCertWithoutDelegationUsage.
const DcKeyWithoutDelegationUsage = `-----BEGIN EC PRIVATE KEY-----
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

// Use with maxVersion == VersionTLS13.
const DcTestDataTLS13PEM = `-----BEGIN DC TEST DATA-----
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
-----END DC TEST DATA-----`

// Parses the input PEM block containing the test DCs.
func dcLoadTestData(in []byte, out *[]dcTestDC) error {
	block, _ := pem.Decode(in)
	if block == nil {
		return errors.New("failed to decode DC tests PEM block")
	}

	// Parse the DER-encoded test DCs.
	_, err := asn1.Unmarshal(block.Bytes, out)
	if err != nil {
		return errors.New("failed to unmarshal DC test ASN.1 data")
	}

	// Check we can parse the DCs
	for _, test := range *out {
		_, err := unmarshalDelegatedCredential(test.DC)
		if err != nil {
			return err
		}
	}
	return nil
}

var dcTestDCs []dcTestDC
var dcTestConfig *Config
var dcTestDelegationCert Certificate
var dcTestCert Certificate
var dcTestNow time.Time

func init() {
	// Load the DC test data.
	var testData []byte
	if maxVersion != 0x0304 {
		panic(fmt.Errorf("no test data for version %04x", maxVersion))
	}
	testData = []byte(DcTestDataTLS13PEM)

	err := dcLoadTestData(testData, &dcTestDCs)
	if err != nil {
		panic(err)
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
	dcTestDelegationCert, err = X509KeyPair([]byte(DcCertWithDelegationUsage), []byte(DcKeyWithDelegationUsage))
	if err != nil {
		panic(err)
	}
	dcTestDelegationCert.Leaf, err = x509.ParseCertificate(dcTestDelegationCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// A certificate without the the DelegationUsage extension for X.509.
	dcTestCert, err = X509KeyPair([]byte(DcCertWithoutDelegationUsage), []byte(DcKeyWithoutDelegationUsage))
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
