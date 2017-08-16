// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGetCertificateFunctionWithInvalidSignatureScheme(t *testing.T) {
	cert := getTLSCertificate(testDelUsageECCertificate, testDelUsageECPrivateKey)
	clientHelloInfo := &ClientHelloInfo{
		CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedVersions: []uint16{VersionTLS12},
	}
	getCertificateFn := NewDelegatedCredentialsGetCertificate(cert)

	_, err := getCertificateFn(clientHelloInfo)
	expectError(err, "No valid signature scheme", t)

	clientHelloInfo.SignatureSchemes = []SignatureScheme{PKCS1WithSHA256} // hash ok, but incompatible with EC
	_, err = getCertificateFn(clientHelloInfo)
	expectError(err, "No valid signature scheme", t)

	clientHelloInfo.SignatureSchemes = []SignatureScheme{PKCS1WithSHA384}
	_, err = getCertificateFn(clientHelloInfo)
	expectError(err, "No valid signature scheme", t)

	clientHelloInfo.SignatureSchemes = []SignatureScheme{ECDSAWithP521AndSHA512}
	_, err = getCertificateFn(clientHelloInfo)
	expectError(err, "No valid signature scheme", t)

	clientHelloInfo.SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256}
	_, err = getCertificateFn(clientHelloInfo)
	expectError(err, "", t)
}

func TestGetCertificateFunctionWithInvalidCertificate(t *testing.T) {
	cert := getTLSCertificate(testNoDelUsageRSACertificate, testNoDelUsageRSAPrivateKey)
	clientHelloInfo := &ClientHelloInfo{
		CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{VersionTLS12},
	}
	getCertificateFn := NewDelegatedCredentialsGetCertificate(cert)

	_, err := getCertificateFn(clientHelloInfo)
	expectError(err, "Delegated Credentials not supported by the certificate (DelegationUsage extension missing)", t)
}

func TestGetCertificateFunction(t *testing.T) {
	cert := getTLSCertificate(testDelUsageECCertificate, testDelUsageECPrivateKey)
	clientHelloInfo := &ClientHelloInfo{
		CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{VersionTLS12},
	}
	getCertificateFn := NewDelegatedCredentialsGetCertificate(cert)

	delCredCert, err := getCertificateFn(clientHelloInfo)
	expectError(err, "", t)

	if delCredCert.PrivateKey == nil || delCredCert.DelegatedCredential == nil {
		t.Error("Certificate's delegated key or credential is unexpectedly nil")
	}
}

func TestSelectSignatureScheme(t *testing.T) {
	certificate, _ := getCertAndKey(testDelUsageECCertificate, testDelUsageECPrivateKey)
	schemes := []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512}
	if s := selectSignatureScheme(schemes, certificate); s != ECDSAWithP256AndSHA256 {
		t.Errorf("Incorrect signature scheme selected (0x%04X)", s)
	}
	schemes = []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256}
	if s := selectSignatureScheme(schemes, certificate); s != ECDSAWithP256AndSHA256 {
		t.Errorf("Incorrect signature scheme selected (0x%04X)", s)
	}
	schemes = []SignatureScheme{PSSWithSHA256}
	if s := selectSignatureScheme(schemes, certificate); s != 0 {
		t.Error("Incorrect signature scheme selected, assumed zero")
	}

	certificate, _ = getCertAndKey(testDelUsageRSACertificate, testDelUsageRSAPrivateKey)
	schemes = []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256}
	if s := selectSignatureScheme(schemes, certificate); s != PSSWithSHA256 {
		t.Errorf("Incorrect signature scheme selected (0x%04X)", s)
	}
}

func TestIsCertificateValid(t *testing.T) {
	certRSA, _ := getCertAndKey(testDelUsageRSACertificate, testDelUsageRSAPrivateKey)
	certEC, _ := getCertAndKey(testDelUsageECCertificate, testDelUsageECPrivateKey)
	if !isCertificateValidForDelegationUsage(certRSA) || !isCertificateValidForDelegationUsage(certEC) {
		t.Errorf("Expected certificate to be valid for DelegationUsage")
	}
	certRSA, _ = getCertAndKey(testNoDelUsageRSACertificate, testNoDelUsageRSAPrivateKey)
	if isCertificateValidForDelegationUsage(certRSA) == true {
		t.Errorf("Expected certificate not to be valid for DelegationUsage")
	}
}

func TestMarshalling(t *testing.T) {
	cert := getTLSCertificate(testDelUsageECCertificate, testDelUsageECPrivateKey)
	validTill := time.Now().Add(CredentialsValidity)
	relativeToCert := validTill.Sub(cert.Leaf.NotBefore)

	credentialBefore := DelegatedCredential{
		ValidTime: int64(relativeToCert.Seconds()),
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credentialBefore.PublicKey = privateKey.Public()

	credentialBytes, err := credentialBefore.marshalAndSign(cert, SignatureScheme(ECDSAWithP256AndSHA256), VersionTLS12)
	credentialAfter, err := unmarshalAndVerify(credentialBytes, cert.Leaf, VersionTLS11) // wrong version -> wrong signature -> error
	expectError(err, "ECDSA verification failed", t)
	credentialAfter, err = unmarshalAndVerify(credentialBytes, cert.Leaf, VersionTLS12) // correct version -> ok
	expectError(err, "", t)

	if credentialBefore.ValidTime != credentialAfter.ValidTime {
		t.Error("Marshalling delegated credentials unexpectedly altered ValidTime")
	}
	a, _ := x509.MarshalPKIXPublicKey(credentialBefore.PublicKey)
	b, _ := x509.MarshalPKIXPublicKey(credentialAfter.PublicKey)
	if !bytes.Equal(a, b) {
		t.Error("Marshalling delegated credentials unexpectedly altered its PublicKey")
	}
}

// ---------------- integration tests ---------------- //

// TLS 1.2 RSA with DC
func TestDelegatedCredentialsHandshake12RSA(t *testing.T) {
	testCase := testCase{
		ClientConfig:      testConfig.Clone(),
		ServerConfig:      testConfig.Clone(),
		NumOfClientWrites: 2,
		NumOfServerWrites: 2,
	}
	testCase.ClientConfig.UseDelegatedCredentials = true
	testCase.ClientConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}
	testCase.ServerConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}

	cert, key := getCertAndKey(testDelUsageRSACertificate, testDelUsageRSAPrivateKey)
	certificate := &Certificate{
		Certificate: [][]byte{cert.Raw},
		Leaf:        cert,
		PrivateKey:  key,
	}
	testCase.ServerConfig.Certificates = nil
	testCase.ServerConfig.GetCertificate = NewDelegatedCredentialsGetCertificate(certificate)
	testCase.doHandshake(t)
}

// TLS 1.2 ECDHE+ECSDA with DC
func TestDelegatedCredentialsHandshake12EC(t *testing.T) {
	testCase := testCase{
		ClientConfig:      testConfig.Clone(),
		ServerConfig:      testConfig.Clone(),
		NumOfClientWrites: 2,
		NumOfServerWrites: 2,
	}
	testCase.ClientConfig.UseDelegatedCredentials = true
	testCase.ClientConfig.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	testCase.ServerConfig.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	cert, key := getCertAndKey(testDelUsageECCertificate, testDelUsageECPrivateKey)
	certificate := &Certificate{
		Certificate: [][]byte{cert.Raw},
		Leaf:        cert,
		PrivateKey:  key,
	}
	testCase.ServerConfig.Certificates = nil
	testCase.ServerConfig.GetCertificate = NewDelegatedCredentialsGetCertificate(certificate)
	testCase.doHandshake(t)
}

// ---------------- helper functions and test keys ---------------- //

func getTLSCertificate(cert string, privateKey string) *Certificate {
	endCert, key := getCertAndKey(cert, privateKey)
	return &Certificate{
		Certificate: [][]byte{endCert.Raw},
		PrivateKey:  key,
		Leaf:        endCert,
	}
}

func expectError(err error, expectedError string, t *testing.T) {
	if expectedError != "" {
		if err == nil {
			t.Errorf("client unexpectedly returned no error")
		}
		if e := err.Error(); !strings.Contains(e, expectedError) {
			t.Errorf("expected to find %q in error but error was %q", expectedError, e)
		}
	} else {
		if err != nil {
			t.Errorf("Expected no error, but received %q", err.Error())
		}
	}
}

type testCase struct {
	ClientConfig           *Config
	ServerConfig           *Config
	ExpectedClientErrorMsg string
	ExpectedServerErrorMsg string
	NumOfClientWrites      int
	NumOfServerWrites      int
}

func (testCase testCase) doHandshake(t *testing.T) {
	c, s := net.Pipe()
	clientWCC := &writeCountingConn{Conn: c}
	serverWCC := &writeCountingConn{Conn: s}
	done := make(chan bool)

	go func() {
		err := Server(serverWCC, testCase.ServerConfig).Handshake()
		expectError(err, testCase.ExpectedServerErrorMsg, t)
		serverWCC.Close()
		done <- true
	}()

	err := Client(clientWCC, testCase.ClientConfig).Handshake()
	expectError(err, testCase.ExpectedClientErrorMsg, t)
	clientWCC.Close()
	<-done

	// num of writes check
	if n := clientWCC.numWrites; n != testCase.NumOfClientWrites {
		t.Errorf("expected client handshake to complete with %d write, but saw %d", testCase.NumOfClientWrites, n)
	}
	if n := serverWCC.numWrites; n != testCase.NumOfServerWrites {
		t.Errorf("expected server handshake to complete with %d write, but saw %d", testCase.NumOfServerWrites, n)
	}
}

const testNoDelUsageRSACertificate = `
-----BEGIN CERTIFICATE-----
MIIB7zCCAVigAwIBAgIQXBnBiWWDVW/cC8m5k5/pvDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE2MDgxNzIxNTIzMVoXDTE3MDgxNzIxNTIz
MVowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAum+qhr3Pv5/y71yUYHhv6BPy0ZZvzdkybiI3zkH5yl0prOEn2mGi7oHLEMff
NFiVhuk9GeZcJ3NgyI14AvQdpJgJoxlwaTwlYmYqqyIjxXuFOE8uCXMyp70+m63K
hAfmDzr/d8WdQYUAirab7rCkPy1MTOZCPrtRyN1IVPQMjkcCAwEAAaNGMEQwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
DwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOBgQBGq0Si+yhU+Fpn+GKU
8ZqyGJ7ysd4dfm92lam6512oFmyc9wnTN+RLKzZ8Aa1B0jLYw9KT+RBrjpW5LBeK
o0RIvFkTgxYEiKSBXCUNmAysEbEoVr4dzWFihAm/1oDGRY2CLLTYg5vbySK3KhIR
e/oCO8HJ/+rJnahJ05XX1Q7lNQ==
-----END CERTIFICATE-----`

const testNoDelUsageRSAPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC6b6qGvc+/n/LvXJRgeG/oE/LRlm/N2TJuIjfOQfnKXSms4Sfa
YaLugcsQx980WJWG6T0Z5lwnc2DIjXgC9B2kmAmjGXBpPCViZiqrIiPFe4U4Ty4J
czKnvT6brcqEB+YPOv93xZ1BhQCKtpvusKQ/LUxM5kI+u1HI3UhU9AyORwIDAQAB
AoGAEJZ03q4uuMb7b26WSQsOMeDsftdatT747LGgs3pNRkMJvTb/O7/qJjxoG+Mc
qeSj0TAZXp+PXXc3ikCECAc+R8rVMfWdmp903XgO/qYtmZGCorxAHEmR80SrfMXv
PJnznLQWc8U9nphQErR+tTESg7xWEzmFcPKwnZd1xg8ERYkCQQDTGtrFczlB2b/Z
9TjNMqUlMnTLIk/a/rPE2fLLmAYhK5sHnJdvDURaH2mF4nso0EGtENnTsh6LATnY
dkrxXGm9AkEA4hXHG2q3MnhgK1Z5hjv+Fnqd+8bcbII9WW4flFs15EKoMgS1w/PJ
zbsySaSy5IVS8XeShmT9+3lrleed4sy+UwJBAJOOAbxhfXP5r4+5R6ql66jES75w
jUCVJzJA5ORJrn8g64u2eGK28z/LFQbv9wXgCwfc72R468BdawFSLa/m2EECQGbZ
rWiFla26IVXV0xcD98VWJsTBZMlgPnSOqoMdM1kSEd4fUmlAYI/dFzV1XYSkOmVr
FhdZnklmpVDeu27P4c0CQQCuCOup0FlJSBpWY1TTfun/KMBkBatMz0VMA3d7FKIU
csPezl677Yjo8u1r/KzeI6zLg87Z8E6r6ZWNc9wBSZK6
-----END RSA PRIVATE KEY-----`

const testDelUsageRSACertificate = `
-----BEGIN CERTIFICATE-----
MIIFcTCCA1mgAwIBAgIJANn//ZDbk3v3MA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
c2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQ8wDQYDVQQLDAZD
bGllbnQwHhcNMTcwNzExMTMxOTM2WhcNMjcwNzA5MTMxOTM2WjBsMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNj
bzEfMB0GA1UECgwWSW50ZXJuZXQgV2lkZ2V0cywgSW5jLjEPMA0GA1UECwwGQ2xp
ZW50MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApYjTp0KaAdJmec9o
iwBet8JxFnGXnfaDeAPMtD+diTD7Z9NYdQijQT9MQJeoX8p9Cs93+xVvlxwDXniU
5xkZQTGwBcti48QpUdz1khJgFlYFkd0HZLb+2cEhSDoBuahQ+6KAq5PF0lI0zLFX
2cPfttNdlWBQi+/d0RBlNcAenUqNbuw8/4+dfM/EstC/2PHfkq9XxnnZJFxl/4G/
+wmKuFQsPXoHXmswdjuKVcu37jwkguBjEEIh+v9tlr4YbfzGrdq4upoyjE2M1uwq
C4EC+roWTKQ6/ZnG0l4bQq9suX3YgJGi7KummHUkxNdHMVgkxqyf46lcapVNnQZG
/CGv50ihqz3X4+rv5h/x0Q75tcMGO+9T3E7yfbNp22bN16znlF4xlUsV2nPqhcLt
STrgQ50cIvUNWHtLtzyqN6MGQhju16So+bUfJlaA5y8B9p0APCyW9Xn4HqygsF3j
FAutw4H4RKzFDNqUG6TtYA2yl2BWz4Gu4o90TdnbOztPRxkpDAaYV6NDCQCGe9o7
G+3TISmGQu1Zsvq/b+rHH/FVNVkAIm69xkvufrDpjUOUyj+x7Z7GB+sGhLEbXCzu
hWWocsRS9LM6ERhDtz8v+PZozTzX8rXRp2j02Y2FpKCFSwfLYn6rsbMBLmS9D92r
bhnvEMO5xhEM374boWbkSooWDJMCAwEAAaMWMBQwEgYDVR1jBAsMCVNvbWV0aGlu
ZzANBgkqhkiG9w0BAQsFAAOCAgEAaW+QI3KcVrMw42i2zY2DmL6DJJQZdBEEWu7p
PCt9veD88Y7lFkwtow2RrcWq6F7dcRNBqU7VA1WJ1yxIWosuTt3PDiTz8MXnt3QD
AY5drJkGOtYxOHVh9pmwrYWI3EH/xbdp0Q3or0TiccZv+WObOPZOvOW7g4P4k2kB
4uWLB5qh5CGTOG8nmAQdDqPd/1zFFfvZQtL8QtYmfFX0KD3HZqHwor06GVeXvnM2
ECJd5LRC0RBVLjQ5ZxmZYuc2B6Azj4C82Djrcnu87HAmj4eZan3VEP/8AdTdE69j
MNTLW+9DWnD/b9yclP8SUUJMPReMEqRP2iImiVHBXKVQFlFgQvoScJ3p0TkXBn3c
t5bThaqIlIbHZ7+5OHIoH1b1Xi93c3nFTAOo8NF9nRyaCc6s/NVvkMp07vL+Q49G
Be7SvKo0GJdDyceDwZp6BlMpzDZoTPxn6V+suEO1mTkRWFE4UNvm8xck28l8P1r0
UettXg/KDehXVgnqfa34esMDUgyukvZ/j2xkmq0KQClR5u9+ghMvYdAX8v32FD/A
5xVOHJSy6IGIJDVog3vRmEHH6sGmxdf6mTeSIsemy0ZxeS7gz323LgE26xgXYzK+
xw90Y6LbNpmd/0VyTfRrsnQfw7uTbwC4TCqZ7E0AE8MJ3D39FJ5M8JTioapSQtj6
GigDdTI=
-----END CERTIFICATE-----
`

const testDelUsageRSAPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

const testDelUsageECCertificate = `
-----BEGIN CERTIFICATE-----
MIIBVTCB/aADAgECAgkAzpPxOO5zqeAwCgYIKoZIzj0EAwIwJTELMAkGA1UEBhMC
YXUxCjAIBgNVBAgMAWExCjAIBgNVBAcMAWQwHhcNMTcwODAxMTQwODExWhcNMjcw
NzMwMTQwODExWjAlMQswCQYDVQQGEwJhdTEKMAgGA1UECAwBYTEKMAgGA1UEBwwB
ZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDa9kSledQJwGL8y2QGyvCcFuCSc
KTnFxv4+vWWbzF4gsIak1K58XQ2z45q1PhQ8v1CsxHUM1RqWOnZ0iBz/bTGjFjAU
MBIGA1UdYwQLDAlTb21ldGhpbmcwCgYIKoZIzj0EAwIDRwAwRAIgVODR7EzCmErD
CssCLEOM5Arw4Tn34mzBh6Z9RlK9jKYCIHiC4lG4Gr223TFdwcYGXB/mQEXhaH2s
W0sa/U27mJcO
-----END CERTIFICATE-----
`

const testDelUsageECPrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMwkWv49XgVX3kfdjPgIZXpUQMEmVakbYfwQXxWcdkhYoAoGCCqGSM49
AwEHoUQDQgAENr2RKV51AnAYvzLZAbK8JwW4JJwpOcXG/j69ZZvMXiCwhqTUrnxd
DbPjmrU+FDy/UKzEdQzVGpY6dnSIHP9tMQ==
-----END EC PRIVATE KEY-----
`

func getCertAndKey(certificate string, privateKey string) (*x509.Certificate, crypto.PrivateKey) {
	keyBlock, _ := pem.Decode([]byte(privateKey))
	certBlock, _ := pem.Decode([]byte(certificate))
	cert, err := x509.ParseCertificate(certBlock.Bytes)

	var key crypto.PrivateKey
	if cert.PublicKeyAlgorithm == x509.RSA {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	} else if cert.PublicKeyAlgorithm == x509.ECDSA {
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	}
	if key == nil || err != nil {
		log.Fatal("Unable to parse test certificate or its private key")
	}

	return cert, key
}
