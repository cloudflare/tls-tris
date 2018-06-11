// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package subcerts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"testing"
	"time"
)

// Load an X.509 certificate from a file.
func loadCert(fn string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse DER encoded certificate")
	}

	// Parse the certficate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Load a DER encoded signing key from a file.
func loadKey(fn string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse DER-encoded ECDSA signing key")
	}

	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

// Load the test keys stored in testdata/.
func newDelegatorFromTestKeys() (*Delegator, *x509.Certificate, error) {
	cert, err := loadCert("testdata/cert.pem")
	if err != nil {
		return nil, nil, err
	}

	sk, err := loadKey("testdata/key.pem")
	if err != nil {
		return nil, nil, err
	}

	del, err := NewDelegator(sk, cert)
	if err != nil {
		return nil, nil, err
	}

	return del, cert, nil
}

func testECDSAPublicKeysEqual(t *testing.T,
	publicKey, publicKey2 crypto.PublicKey, scheme tls.SignatureScheme) {

	curve := getCurve(scheme)
	pk := publicKey.(*ecdsa.PublicKey)
	pk2 := publicKey2.(*ecdsa.PublicKey)
	serializedPublicKey := elliptic.Marshal(curve, pk.X, pk.Y)
	serializedPublicKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
	if !bytes.Equal(serializedPublicKey2, serializedPublicKey) {
		t.Error("PublicKey mismatch")
	}
}

// Test that cred and cred2 are equal.
func testCredentialsEqual(t *testing.T, cred, cred2 *Credential) {
	if cred2.ValidTime != cred.ValidTime {
		t.Errorf("ValidTime mismatch: got %d, expected %d",
			cred2.ValidTime, cred.ValidTime)
	}
	if cred2.scheme != cred.scheme {
		t.Errorf("scheme mismatch: got %04x, expected %04x", cred2.scheme, cred.scheme)
	}

	testECDSAPublicKeysEqual(t, cred.PublicKey, cred2.PublicKey, cred.scheme)
}

// Test the cosntructors for Delegator and Credential.
func TestNewCredentailAndDelegator(t *testing.T) {
	if _, _, err := NewCredential(tls.ECDSAWithP521AndSHA512, MaxValidTime); err != nil {
		t.Error(err)
	}

	if _, _, err := newDelegatorFromTestKeys(); err != nil {
		t.Error(err)
	}
}

// Test that the NewDelegator constructor fails if the certificate doesn't have
// the DelegationUsage extension and the digitalSignature key usage.
func TestNewDelegatorWithoutDelegationUsage(t *testing.T) {
	cert, err := loadCert("testdata/no_dc_cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	sk, err := loadKey("testdata/no_dc_key.pem")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewDelegator(sk, cert); err == nil {
		t.Error("NewDelegator succeeds, expected failure")
	}
}

// Test encoding/decoding of credentials.
func TestCredentialMarshalUnmarshal(t *testing.T) {
	_, cred, err := NewCredential(tls.ECDSAWithP256AndSHA256, MaxValidTime)
	if err != nil {
		t.Fatal(err)
	}

	serializedCred, err := cred.Marshal()
	if err != nil {
		t.Error(err)
	}

	cred2, err := UnmarshalCredential(serializedCred)
	if err != nil {
		t.Error(err)
	}

	testCredentialsEqual(t, cred, cred2)
}

// Test delegation and validation of credentials.
func TestDelegateValidate(t *testing.T) {
	ver := uint16(tls.VersionTLS12)

	del, cert, err := newDelegatorFromTestKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, cred, err := NewCredential(tls.ECDSAWithP256AndSHA256, MaxValidTime)
	if err != nil {
		t.Fatal(err)
	}

	delegatedCred, err := del.Delegate(cred, ver)
	if err != nil {
		t.Error(err)
	}

	// Test validation of good DC.
	if v, err := delegatedCred.Validate(cert, ver, time.Now()); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid, expected valid")
	}

	// Test validation of expired DC.
	if v, err := delegatedCred.Validate(
		cert, ver, time.Now().Add(MaxValidTime).Add(time.Nanosecond)); err == nil {
		t.Error("expired DC validation succeeded, expected failure")
	} else if v {
		t.Error("expired DC is valid, expected invalid")
	}

	// Test protocol binding.
	if v, err := delegatedCred.Validate(
		cert, tls.VersionSSL30, time.Now()); err == nil {
		t.Error("DC validation with wrong version succeeded, expected failure")
	} else if v {
		t.Error("DC with wrong version is valid, expected invalid")
	}

	// Test signature algorithm binding.
	delegatedCred.Scheme = tls.ECDSAWithP521AndSHA512
	if v, err := delegatedCred.Validate(cert, ver, time.Now()); err == nil {
		t.Error("DC validation with wrong scheme succeeded, expected failure")
	} else if v {
		t.Error("DC with wrong scheme is valid, expected invalid")
	}
	delegatedCred.Scheme = tls.ECDSAWithP256AndSHA256

	// Test delegation cedrtificate binding.
	cert.Raw[0] ^= byte(42)
	if v, err := delegatedCred.Validate(cert, ver, time.Now()); err == nil {
		t.Error("DC validation with wrong cert succeeded, expected failure")
	} else if v {
		t.Error("DC with wrong cert is valid, expected invalid")
	}
	cert.Raw[0] ^= byte(42)

	// Test validation of DC who's TTL is too long.
	cred2 := &Credential{
		MaxValidTime + time.Second,
		cred.PublicKey,
		cred.scheme,
	}
	delegatedCred2, err := del.Delegate(cred2, ver)
	if err != nil {
		t.Error(err)
	}
	if v, err := delegatedCred2.Validate(cert, ver, time.Now()); err == nil {
		t.Error("DC validation with long TTL succeeded, expected failure")
	} else if v {
		t.Error("DC with long TTL is valid, expected invalid")
	}

	// Test validation of DC using a certificate that can't delegate.
	cert2, err := loadCert("testdata/no_dc_cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := delegatedCred.Validate(
		cert2, ver, time.Now()); err != errNoDelegationUsage {
		t.Error("DC validation with non-delegation cert succeeded, expected failure")
	} else if v {
		t.Error("DC with non-delegation cert is valid, expected invalid")
	}
}

// Test encoding/decoding of delegated credentials.
func TestDelegatedCredentialMarshalUnmarshal(t *testing.T) {
	del, _, err := newDelegatorFromTestKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, cred, err := NewCredential(tls.ECDSAWithP256AndSHA256, MaxValidTime)
	if err != nil {
		t.Fatal(err)
	}

	delegatedCred, err := del.Delegate(cred, tls.VersionTLS12)
	if err != nil {
		t.Error(err)
	}

	serialized, err := delegatedCred.Marshal()
	if err != nil {
		t.Error(err)
	}

	delegatedCred2, err := UnmarshalDelegatedCredential(serialized)
	if err != nil {
		t.Error(err)
	}

	testCredentialsEqual(t, &delegatedCred.Cred, &delegatedCred2.Cred)

	if delegatedCred.Scheme != delegatedCred2.Scheme {
		t.Errorf("scheme mismatch: got %04x, expected %04x",
			delegatedCred2.Scheme, delegatedCred.Scheme)
	}

	if !bytes.Equal(delegatedCred2.Signature, delegatedCred.Signature) {
		t.Error("Signature mismatch")
	}
}
