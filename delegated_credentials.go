// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

var delegatedCredentialsIdentifier = asn1.ObjectIdentifier{2, 5, 29, 99}

type GetCertificate func(*ClientHelloInfo) (*Certificate, error)

type DelegatedCredential struct {
	ValidTime int64
	PublicKey interface{}
}

type cachedCredential struct {
	credential []byte
	validTime  int64
	privateKey crypto.PrivateKey
}

type credentialsSetup struct {
	scheme   SignatureScheme
	cert     *Certificate
	version  uint16
	validity time.Duration
	timeFunc func() time.Time
}

var cachedCredentials map[SignatureScheme]*cachedCredential

// Creates new GetCertificate function which modifies the certificate
// to include a delegated credential.
func NewDelegatedCredentialsGetCertificate(cert *Certificate, validity time.Duration, timeFunc func() time.Time) GetCertificate {
	return func(clientHelloInfo *ClientHelloInfo) (*Certificate, error) {
		if !isCertificateValidForDelegationUsage(cert.Leaf) {
			return nil, errors.New("tls: Delegated Credentials not supported by the certificate (DelegationUsage extension missing)")
		}
		selectedScheme := selectSignatureScheme(clientHelloInfo.SignatureSchemes, cert.Leaf)
		if selectedScheme == 0 {
			return nil, errors.New("tls: No valid signature scheme found for Delegated Credentials")
		}
		version := selectVersion(clientHelloInfo.SupportedVersions)
		if version == 0 {
			return nil, errors.New("tls: Only TLS 1.2 or 1.3 are supported")
		}

		err := fetchCredentialFromCache(&credentialsSetup{
			scheme:   selectedScheme,
			cert:     cert,
			version:  version,
			validity: validity,
			timeFunc: timeFunc,
		})
		if err != nil {
			return nil, err
		}

		cert.DelegatedCredential = cachedCredentials[selectedScheme].credential
		cert.PrivateKey = cachedCredentials[selectedScheme].privateKey
		return cert, nil
	}
}

// Checks if a credential is already stored in memory. If not or the credential
// is already expired a new credential is created.
func fetchCredentialFromCache(setup *credentialsSetup) (err error) {
	if cachedCredentials == nil {
		cachedCredentials = make(map[SignatureScheme]*cachedCredential)
	}
	if cachedCredentials[setup.scheme] == nil {
		cachedCredentials[setup.scheme], err = newCredential(setup)
	} else {
		err := checkValidity(cachedCredentials[setup.scheme].validTime, setup.cert.Leaf, setup.timeFunc)
		if err != nil {
			cachedCredentials[setup.scheme], err = newCredential(setup)
		}
	}
	return
}

func newCredential(setup *credentialsSetup) (*cachedCredential, error) {
	credential, privateKey, err := createDelegatedCredential(setup)
	credentialBytes, err := credential.marshalAndSign(setup.cert, setup.scheme, setup.version)
	if err != nil {
		return nil, fmt.Errorf("tls: creating Delegated Credential failed (%s)", err)
	}
	return &cachedCredential{
		credential: credentialBytes,
		validTime:  credential.ValidTime,
		privateKey: privateKey,
	}, nil
}

func selectVersion(versions []uint16) uint16 {
	for _, version := range versions {
		if version == VersionTLS13 {
			return VersionTLS13
		} else if version == VersionTLS12 {
			return VersionTLS12
		}
	}
	return 0
}

// Selects signature scheme based on the client's advertised schemes and the cert's capabilities
func selectSignatureScheme(signatureSchemes []SignatureScheme, cert *x509.Certificate) SignatureScheme {
	for _, scheme := range signatureSchemes {
		if cert.PublicKeyAlgorithm == x509.ECDSA && scheme == ECDSAWithP256AndSHA256 {
			return ECDSAWithP256AndSHA256
		} else if cert.PublicKeyAlgorithm == x509.RSA {
			if scheme == PSSWithSHA256 {
				return PSSWithSHA256
			} else if scheme == PKCS1WithSHA256 {
				return PKCS1WithSHA256
			}
		}
	}
	return 0
}

// Creates new Delegated Credential. The type of the credential is decided based on the selected
// SignatureScheme to ensure client's support.
func createDelegatedCredential(setup *credentialsSetup) (credential DelegatedCredential, privateKey crypto.PrivateKey, err error) {
	validTill := setup.timeFunc().Add(setup.validity)
	relativeToCert := validTill.Sub(setup.cert.Leaf.NotBefore)
	credential = DelegatedCredential{
		ValidTime: int64(relativeToCert.Seconds()),
	}

	if setup.scheme == ECDSAWithP256AndSHA256 {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		credential.PublicKey = privateKey.(crypto.Signer).Public()
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		credential.PublicKey = privateKey.(crypto.Decrypter).Public()
	}
	return
}

// Checks certificate if it contains the DelegationUsage extension required
// for Delegated Credentials.
func isCertificateValidForDelegationUsage(certificate *x509.Certificate) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(delegatedCredentialsIdentifier) {
			return true
		}
	}
	return false
}

// Marshals the credential and provides a signature based on the signature
// scheme and the cert's private key.
func (dc *DelegatedCredential) marshalAndSign(cert *Certificate, scheme SignatureScheme, version uint16) ([]byte, error) {
	cred := make([]byte, 2000)
	cred[0] = uint8(dc.ValidTime >> 24)
	cred[1] = uint8(dc.ValidTime >> 16)
	cred[2] = uint8(dc.ValidTime >> 8)
	cred[3] = uint8(dc.ValidTime)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(dc.PublicKey)
	publicKeyLength := len(publicKeyBytes)
	cred[4] = uint8(publicKeyLength >> 16)
	cred[5] = uint8(publicKeyLength >> 8)
	cred[6] = uint8(publicKeyLength)

	copy(cred[7:7+publicKeyLength], publicKeyBytes)

	cred[publicKeyLength+7] = uint8(scheme >> 8) // hash - todo different in 1.3
	cred[publicKeyLength+8] = uint8(scheme)      // signature

	signature, err := sign(cred, cert, scheme, version, publicKeyLength)

	signatureLength := len(signature)
	cred[publicKeyLength+9] = uint8(signatureLength >> 8)
	cred[publicKeyLength+10] = uint8(signatureLength)
	copy(cred[publicKeyLength+11:publicKeyLength+11+signatureLength], signature)

	return cred[0 : publicKeyLength+11+signatureLength], err
}

func checkValidity(validTime int64, certificate *x509.Certificate, now func() time.Time) error {
	validTill := certificate.NotBefore.Add(time.Duration(validTime) * time.Second)
	if validTill.Before(now()) {
		return errors.New("expired")
	}
	return nil
}

// Unmarshals the credential and verifies its signature and its validity.
func unmarshalAndVerify(credentialBytes []byte, certificate *x509.Certificate, version uint16, now func() time.Time) (dc DelegatedCredential, err error) {
	dc = DelegatedCredential{}
	if !isCertificateValidForDelegationUsage(certificate) {
		return dc, fmt.Errorf("tls: delegated credentials not supported by the certificate (DelegationUsage extension missing)")
	}

	dc.ValidTime = int64(credentialBytes[0])<<24 | int64(credentialBytes[1])<<16 | int64(credentialBytes[2])<<8 | int64(credentialBytes[3])
	publicKeyLength := int(credentialBytes[4])<<16 | int(credentialBytes[5])<<8 | int(credentialBytes[6])
	PublicKeyBytes := make([]byte, publicKeyLength)
	copy(PublicKeyBytes, credentialBytes[7:7+publicKeyLength])
	dc.PublicKey, err = x509.ParsePKIXPublicKey(PublicKeyBytes)
	err = checkValidity(dc.ValidTime, certificate, now)
	if err != nil {
		return dc, err
	}

	signatureScheme := SignatureScheme(credentialBytes[publicKeyLength+7])<<8 + SignatureScheme(credentialBytes[publicKeyLength+8])
	if signatureScheme != ECDSAWithP256AndSHA256 && signatureScheme != PSSWithSHA256 && signatureScheme != PKCS1WithSHA256 {
		return dc, errors.New("unsupported signature scheme")
	}

	signatureLength := int(credentialBytes[publicKeyLength+9])<<8 | int(credentialBytes[publicKeyLength+10])
	signature := make([]byte, signatureLength)
	copy(signature, credentialBytes[publicKeyLength+11:publicKeyLength+11+signatureLength])

	err = verify(credentialBytes, certificate, signatureScheme, version, publicKeyLength, signature)
	return
}

func verify(cred []byte, cert *x509.Certificate, scheme SignatureScheme, version uint16, publicKeyLength int, signature []byte) (err error) {
	hashFunc := crypto.SHA256 // only SHA-256 is currently supported
	digest := getHash(cred, cert, version, hashFunc, publicKeyLength)

	if scheme == ECDSAWithP256AndSHA256 {
		ecdsaSig := new(ecdsaSignature)
		_, err = asn1.Unmarshal(signature, ecdsaSig)
		if !ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest, ecdsaSig.R, ecdsaSig.S) {
			err = errors.New("ECDSA verification failed")
		}
	} else if scheme == PSSWithSHA256 {
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		err = rsa.VerifyPSS(cert.PublicKey.(*rsa.PublicKey), hashFunc, digest, signature, opts)
	} else if scheme == PKCS1WithSHA256 {
		err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), hashFunc, digest, signature)
	} else {
		err = errors.New("unknown signature algorithm")
	}

	return err
}

func sign(cred []byte, cert *Certificate, scheme SignatureScheme, version uint16, publicKeyLength int) (signature []byte, err error) {
	hashFunc := crypto.SHA256 // only SHA-256 is currently supported
	digest := getHash(cred, cert.Leaf, version, hashFunc, publicKeyLength)

	var opts crypto.SignerOpts
	if scheme == PSSWithSHA256 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashFunc}
	} else {
		opts = hashFunc
	}
	signature, err = cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest, opts)

	return signature, err
}

// Returns hash of the credential adding some additional fields
// as defined in the RFC draft.
func getHash(cred []byte, certificate *x509.Certificate, version uint16, hashFunc crypto.Hash, publicKeyLength int) []byte {
	// 64x 0x20, 33 long string, version, DER certificate, signature scheme, DC data
	toSign := make([]byte, 64+33+2+len(certificate.RawTBSCertificate)+2+4+publicKeyLength)
	for i := 0; i < 64; i++ {
		toSign[i] = 0x20
	}
	copy(toSign[64:97], []byte("TLS, server delegated credentials"))
	toSign[97] = uint8(version >> 8)
	toSign[98] = uint8(version)

	copy(toSign[99:99+len(certificate.RawTBSCertificate)], certificate.RawTBSCertificate)
	toSign[99+len(certificate.RawTBSCertificate)] = 4
	toSign[100+len(certificate.RawTBSCertificate)] = 8
	copy(toSign[101+len(certificate.RawTBSCertificate):101+len(certificate.RawTBSCertificate)+4+publicKeyLength], cred[0:4+publicKeyLength])

	hash := hashFunc.New()
	hash.Write(toSign)
	return hash.Sum(nil)
}
