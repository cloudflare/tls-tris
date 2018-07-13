// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

// dcWithPrivateKey stores a delegated credential and its corresponding private
// key.
type dcWithPrivateKey struct {
	*DelegatedCredential
	privateKey crypto.PrivateKey
}

// These test keys were generated with the following program, available in the
// crypto/tls directory:
//
//		go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -dc
//
// To get a certificate without the DelegationUsage extension, remove the `-dc`
// parameter.
var delegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIQLVIvEpo0/0TzRja4ImvB1TAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDcwMzE2NTE1M1oXDTE5MDcwMzE2NTE1M1ow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOhB
U6adaAgliLaFc1PAo9HBO4Wish1G4df3IK5EXLy+ooYfmkfzT1FxqbNLZufNYzve
25fmpal/1VJAjpVyKq2jVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKwYBBAGC
2kssBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPNwRk6cygm6zO5rjOzohKYWS+1KuWCM
OetDIvU4mdyoAiAGN97y3GJccYn9ZOJS4UOqhr9oO8PuZMLgdq4OrMRiiA==
-----END CERTIFICATE-----
`

var delegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJDVlo+sJolMcNjMkfCGDUjMJcE4UgclcXGCrOtbJAi2oAoGCCqGSM49
AwEHoUQDQgAE6EFTpp1oCCWItoVzU8Cj0cE7haKyHUbh1/cgrkRcvL6ihh+aR/NP
UXGps0tm581jO97bl+alqX/VUkCOlXIqrQ==
-----END EC PRIVATE KEY-----
`

var nonDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBaTCCAQ6gAwIBAgIQSUo+9uaip3qCW+1EPeHZgDAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDYxMjIzNDAyNloXDTE5MDYxMjIzNDAyNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLf7
fiznPVdc3V5mM3ymswU2/IoJaq/deA6dgdj50ozdYyRiAPjxzcz9zRsZw1apTF/h
yNfiLhV4EE1VrwXcT5OjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0E
AwIDSQAwRgIhANXG0zmrVtQBK0TNZZoEGMOtSwxmiZzXNe+IjdpxO3TiAiEA5VYx
0CWJq5zqpVXbJMeKVMASo2nrXZoA6NhJvFQ97hw=
-----END CERTIFICATE-----
`

var nonDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMw9DiOfGI1E/XZrrW2huZSjYi0EKwvVjAe+dYtyFsSloAoGCCqGSM49
AwEHoUQDQgAEt/t+LOc9V1zdXmYzfKazBTb8iglqr914Dp2B2PnSjN1jJGIA+PHN
zP3NGxnDVqlMX+HI1+IuFXgQTVWvBdxPkw==
-----END EC PRIVATE KEY-----
`

// Invalid TLS versions used for testing purposes.
const (
	versionInvalidDC     uint16 = 0xff00
	versionMalformedDC12 uint16 = 0xff12
	versionMalformedDC13 uint16 = 0xff13
)

var dcTestConfig *Config
var dcTestCerts map[string]*Certificate
var dcTestDCs map[uint16]dcWithPrivateKey
var dcNow time.Time
var dcTestDCScheme = ECDSAWithP521AndSHA512
var dcTestDCVersions = []uint16{
	VersionTLS12,
	VersionTLS13,
	VersionTLS13Draft23,
	versionInvalidDC,
}

func init() {

	// Use a static time for testing at whcih time the test certificates are
	// valid.
	dcNow = time.Date(2018, 07, 03, 18, 0, 0, 234234, time.UTC)

	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS10,
		MaxVersion:   VersionTLS13Draft22,
		CipherSuites: allCipherSuites(),
	}

	// The certificates of the server.
	dcTestCerts = make(map[string]*Certificate)
	var err error

	// The delegation certificate.
	dcCert := new(Certificate)
	*dcCert, err = X509KeyPair([]byte(delegatorCertPEM), []byte(delegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	dcCert.Leaf, err = x509.ParseCertificate(dcCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dc"] = dcCert

	// The standard certificate.
	ndcCert := new(Certificate)
	*ndcCert, err = X509KeyPair([]byte(nonDelegatorCertPEM), []byte(nonDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	ndcCert.Leaf, err = x509.ParseCertificate(ndcCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["no dc"] = ndcCert

	// The root certificates for the client.
	dcTestConfig.RootCAs = x509.NewCertPool()

	dcRoot, err := x509.ParseCertificate(dcCert.Certificate[len(dcCert.Certificate)-1])
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(dcRoot)

	ndcRoot, err := x509.ParseCertificate(ndcCert.Certificate[len(ndcCert.Certificate)-1])
	if err != nil {
		panic(err)
	}
	dcTestConfig.RootCAs.AddCert(ndcRoot)

	// A pool of DCs.
	dcTestDCs = make(map[uint16]dcWithPrivateKey)
	for _, vers := range dcTestDCVersions {
		dc, sk, err := NewDelegatedCredential(dcCert, dcTestDCScheme, dcNow.Sub(dcCert.Leaf.NotBefore)+dcMaxTTL, vers)
		if err != nil {
			panic(err)
		}
		dcTestDCs[vers] = dcWithPrivateKey{dc, sk}
	}
	// Add two DCs with invalid private keys, one for TLS 1.2 and another for
	// 1.3.
	malformedDC12 := new(DelegatedCredential)
	*malformedDC12 = *dcTestDCs[VersionTLS12].DelegatedCredential
	dcTestDCs[versionMalformedDC12] = dcWithPrivateKey{
		malformedDC12,
		dcTestDCs[versionInvalidDC].privateKey,
	}
	malformedDC13 := new(DelegatedCredential)
	*malformedDC13 = *dcTestDCs[VersionTLS13].DelegatedCredential
	dcTestDCs[versionMalformedDC13] = dcWithPrivateKey{
		malformedDC13,
		dcTestDCs[versionInvalidDC].privateKey,
	}
}

func checkECDSAPublicKeysEqual(
	publicKey, publicKey2 crypto.PublicKey, scheme SignatureScheme) error {

	curve := getCurve(scheme)
	pk := publicKey.(*ecdsa.PublicKey)
	pk2 := publicKey2.(*ecdsa.PublicKey)
	serializedPublicKey := elliptic.Marshal(curve, pk.X, pk.Y)
	serializedPublicKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
	if !bytes.Equal(serializedPublicKey2, serializedPublicKey) {
		return errors.New("PublicKey mismatch")
	}

	return nil
}

// Test that cred and cred2 are equal.
func checkCredentialsEqual(dc, dc2 *DelegatedCredential) error {
	if dc2.Cred.ValidTime != dc.Cred.ValidTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", dc2.Cred.ValidTime, dc.Cred.ValidTime)
	}
	if dc2.Cred.scheme != dc.Cred.scheme {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", dc2.Cred.scheme, dc.Cred.scheme)
	}

	return checkECDSAPublicKeysEqual(dc.Cred.PublicKey, dc2.Cred.PublicKey, dc.Cred.scheme)
}

// Test delegation and validation of credentials.
func TestDelegateValidate(t *testing.T) {
	ver := uint16(VersionTLS12)
	cert := dcTestCerts["dc"]

	validTime := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL
	shortValidTime := dcNow.Sub(cert.Leaf.NotBefore) + time.Second

	delegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, validTime, ver)
	if err != nil {
		t.Fatal(err)
	}

	// Test validation of good DC.
	if v, err := delegatedCred.Validate(cert.Leaf, ver, dcNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of expired DC.
	tooLate := dcNow.Add(dcMaxTTL).Add(time.Nanosecond)
	if v, err := delegatedCred.Validate(cert.Leaf, ver, tooLate); err == nil {
		t.Error("expired DC validation succeeded; want failure")
	} else if v {
		t.Error("expired DC is valid; want invalid")
	}

	// Test protocol binding.
	if v, err := delegatedCred.Validate(cert.Leaf, VersionSSL30, dcNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong version is valid; want invalid")
	}

	// Test signature algorithm binding.
	delegatedCred.Scheme = ECDSAWithP521AndSHA512
	if v, err := delegatedCred.Validate(cert.Leaf, ver, dcNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong scheme is valid; want invalid")
	}
	delegatedCred.Scheme = ECDSAWithP256AndSHA256

	// Test delegation cedrtificate binding.
	cert.Leaf.Raw[0] ^= byte(42)
	if v, err := delegatedCred.Validate(cert.Leaf, ver, dcNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong cert is valid; want invalid")
	}
	cert.Leaf.Raw[0] ^= byte(42)

	// Test validation of DC who's TTL is too long.
	delegatedCred2, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, validTime+time.Second, ver)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := delegatedCred2.Validate(cert.Leaf, ver, dcNow); err == nil {
		t.Error("DC validation with long TTL succeeded; want failure")
	} else if v {
		t.Error("DC with long TTL is valid; want invalid")
	}

	// Test validation of DC who's TTL is short.
	delegatedCred3, _, err := NewDelegatedCredential(cert, ECDSAWithP256AndSHA256, shortValidTime, ver)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := delegatedCred3.Validate(cert.Leaf, ver, dcNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if v, err := delegatedCred.Validate(
		dcTestCerts["no dc"].Leaf, ver, dcNow); err != errNoDelegationUsage {
		t.Error("DC validation with non-delegation cert succeeded; want failure")
	} else if v {
		t.Error("DC with non-delegation cert is valid; want invalid")
	}
}

// Test encoding/decoding of delegated credentials.
func TestDelegatedCredentialMarshalUnmarshal(t *testing.T) {
	cert := dcTestCerts["dc"]
	delegatedCred, _, err := NewDelegatedCredential(cert,
		ECDSAWithP256AndSHA256,
		dcNow.Sub(cert.Leaf.NotBefore)+dcMaxTTL,
		VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := delegatedCred.Marshal()
	if err != nil {
		t.Error(err)
	}

	delegatedCred2, err := UnmarshalDelegatedCredential(serialized)
	if err != nil {
		t.Error(err)
	}

	err = checkCredentialsEqual(delegatedCred, delegatedCred2)
	if err != nil {
		t.Error(err)
	}

	if delegatedCred.Scheme != delegatedCred2.Scheme {
		t.Errorf("scheme mismatch: got %04x; want %04x",
			delegatedCred2.Scheme, delegatedCred.Scheme)
	}

	if !bytes.Equal(delegatedCred2.Signature, delegatedCred.Signature) {
		t.Error("Signature mismatch")
	}
}

// Tests the handshake and one round of application data. Returns true if the
// connection used a DC.
func testConnWithDC(t *testing.T,
	clientMsg, serverMsg string,
	clientConfig, serverConfig *Config) (bool, error) {

	ln := newLocalListener(t)
	defer ln.Close()

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

	cli, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, err
	}
	defer cli.Close()

	srv := <-srvCh
	if srv == nil {
		return false, serr
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	cli.Write([]byte(clientMsg))
	n, err := srv.Read(buf)
	if n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	srv.Write([]byte(serverMsg))
	n, err = cli.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	// Return true if the client's conn.dc structure was instantiated.
	return (cli.verifiedDc != nil), nil
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
		return dcTestCerts["dc"], nil
	}
	return dcTestCerts["no dc"], nil
}

// Checks that the ciient supports the signature algorithm supported by the test
// server, and that the server has a DC for the selected protocol version.
func testServerGetDC(ch *ClientHelloInfo, vers uint16) (*DelegatedCredential, crypto.PrivateKey, error) {
	schemeOk := false
	for _, scheme := range ch.SignatureSchemes {
		schemeOk = schemeOk || (scheme == dcTestDCScheme)
	}

	versOk := false
	for _, testVers := range dcTestDCVersions {
		versOk = versOk || (vers == testVers)
	}

	if schemeOk && versOk && ch.AcceptsDelegatedCredential {
		d := dcTestDCs[vers]
		return d.DelegatedCredential, d.privateKey, nil
	}
	return nil, nil, nil
}

// Returns a DC signed with a bad version number.
func testServerGetInvalidDC(ch *ClientHelloInfo, vers uint16) (*DelegatedCredential, crypto.PrivateKey, error) {
	d := dcTestDCs[versionInvalidDC]
	return d.DelegatedCredential, d.privateKey, nil
}

// Returns a DC with the wrong private key.
func testServerGetMalformedDC(ch *ClientHelloInfo, vers uint16) (*DelegatedCredential, crypto.PrivateKey, error) {
	if vers == VersionTLS12 {
		d := dcTestDCs[versionMalformedDC12]
		return d.DelegatedCredential, d.privateKey, nil
	} else if vers == VersionTLS13 {
		d := dcTestDCs[versionMalformedDC13]
		return d.DelegatedCredential, d.privateKey, nil
	} else {
		return nil, nil, fmt.Errorf("testServerGetMalformedDC: unsupported version %x", vers)
	}

}

var dcTests = []struct {
	clientDC         bool
	serverDC         bool
	clientSkipVerify bool
	clientMaxVers    uint16
	serverMaxVers    uint16
	useMalformedDC   bool
	useInvalidDC     bool
	expectSuccess    bool
	expectDC         bool
	name             string
}{
	{true, true, false, VersionTLS12, VersionTLS12, false, false, true, true, "tls12"},
	{true, true, false, VersionTLS13, VersionTLS13, false, false, true, true, "tls13"},
	{true, true, false, VersionTLS12, VersionTLS12, true, false, false, false, "tls12, malformed dc"},
	{true, true, false, VersionTLS13, VersionTLS13, true, false, false, false, "tls13, malformed dc"},
	{true, true, true, VersionTLS12, VersionTLS12, false, true, true, true, "tls12, invalid dc, skip verify"},
	{true, true, true, VersionTLS13, VersionTLS13, false, true, true, true, "tls13, invalid dc, skip verify"},
	{false, true, false, VersionTLS12, VersionTLS12, false, false, true, false, "client no dc"},
	{true, false, false, VersionTLS12, VersionTLS12, false, false, true, false, "server no dc"},
	{true, true, false, VersionTLS11, VersionTLS12, false, false, true, false, "client old"},
	{true, true, false, VersionTLS12, VersionTLS11, false, false, true, false, "server old"},
}

// Tests the handshake with the delegated credential extension.
func TestDCHandshake(t *testing.T) {
	serverMsg := "hello"
	clientMsg := "world"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetCertificate

	for i, test := range dcTests {
		clientConfig.AcceptDelegatedCredential = test.clientDC
		clientConfig.InsecureSkipVerify = test.clientSkipVerify

		if test.serverDC {
			if test.useInvalidDC {
				serverConfig.GetDelegatedCredential = testServerGetInvalidDC
			} else if test.useMalformedDC {
				serverConfig.GetDelegatedCredential = testServerGetMalformedDC
			} else {
				serverConfig.GetDelegatedCredential = testServerGetDC
			}
		} else {
			serverConfig.GetDelegatedCredential = nil
		}

		clientConfig.MaxVersion = test.clientMaxVers
		serverConfig.MaxVersion = test.serverMaxVers

		usedDC, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig)
		if err != nil && test.expectSuccess {
			t.Errorf("test #%d (%s) fails: %s", i+1, test.name, err)
		} else if err == nil && !test.expectSuccess {
			t.Errorf("test #%d (%s) succeeds; expected failure", i+1, test.name)
		}

		if usedDC != test.expectDC {
			t.Errorf("test #%d (%s) usedDC = %v; expected %v", i+1, test.name, usedDC, test.expectDC)
		}
	}
}
