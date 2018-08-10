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
// specified in https://tools.ietf.org/html/draft-ietf-tls-subcerts-02.
const DcCertWithDelegationUsage = `-----BEGIN CERTIFICATE-----
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
const DcKeyWithDelegationUsage = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAS/pGktmxK1hlt3gF4N2nkMrJnoZihvOO63nnNcxXQroAoGCCqGSM49
AwEHoUQDQgAE3ELrmlDSd5KihrOAwXSVXe81s8hgDU+LgTRlZGdnIGg7HRZ8ffXx
om34KFnq/By7fWfkuh7PvGwzwRzYE0fy3w==
-----END EC PRIVATE KEY-----
`

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

// Test data used for testing the TLS handshake with the delegated credential
// extension. The PEM block encodes a DER encoded slice of dcTestDCs.

// Use with maxVersion == VersionTLS13Draft28.
//
// TODO(henrydcase): Remove this when we drop support for draft28.
const DcTestDataDraft28PEM = `-----BEGIN DC TEST DATA-----
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
-----END DC TEST DATA-----
`

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

	// Check that the test data is for the right version. This should be
	// maxVersion, defined in common.go.
	for _, test := range *out {
		dc, err := unmarshalDelegatedCredential(test.DC)
		if err != nil {
			return err
		}

		// Sanity check that test version matches the version encoded by the DC.
		testVersion := uint16(test.Version)
		if dc.cred.expectedVersion != testVersion {
			return fmt.Errorf(
				"test version doesn't match credential version: got: 0x0%04x; want: 0x%04x",
				testVersion, dc.cred.expectedVersion)
		}

		// With the exception of "badvers" and "tsl12", all test DCs should have
		// the expected verison.
		if test.Name != "badvers" && test.Name != "tls12" && testVersion != maxVersion {
			return fmt.Errorf(
				"encountered test with wrong version: got: 0x0%04x; want: 0x%04x",
				test.Version, maxVersion)
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
	switch maxVersion {
	case VersionTLS13Draft28:
		testData = []byte(DcTestDataDraft28PEM)
	case 0x0304: // TODO(henrydcase): Fix once the final version is implemented
		testData = []byte(DcTestDataTLS13PEM)
	default:
		panic(fmt.Errorf("no test data for version %04x", maxVersion))
	}
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
