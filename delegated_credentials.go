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

const (
	CredentialsValidity time.Duration = 5 * time.Minute
)

var DelegatedCredentialsIdentifier = asn1.ObjectIdentifier{2, 5, 29, 99}

type GetCertificate func(*ClientHelloInfo) (*Certificate, error)

type DelegatedCredential struct {
	ValidTime int64
	PublicKey interface{}
}

func NewDelegatedCredentialsGetCertificate(cert *Certificate) GetCertificate {

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

		// todo "caching"
		credential, privateKey, err := createDelegatedCredential(cert.Leaf, selectedScheme)
		credentialBytes, err := credential.marshalAndSign(cert, selectedScheme, version)
		if err != nil {
			return nil, fmt.Errorf("tls: creating Delegated Credential failed (%s)", err)
		}

		cert.DelegatedCredential = credentialBytes
		cert.PrivateKey = privateKey
		return cert, nil
	}
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
// SignatureScheme to ensure client's support
func createDelegatedCredential(certificate *x509.Certificate, scheme SignatureScheme) (credential DelegatedCredential, privateKey crypto.PrivateKey, err error) {
	validTill := time.Now().Add(CredentialsValidity)
	relativeToCert := validTill.Sub(certificate.NotBefore)
	credential = DelegatedCredential{
		ValidTime: int64(relativeToCert.Seconds()),
	}

	if scheme == ECDSAWithP256AndSHA256 {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		credential.PublicKey = privateKey.(crypto.Signer).Public()
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		credential.PublicKey = privateKey.(crypto.Decrypter).Public()
	}
	return
}

// Checks certificate if it contains the DelegationUsage extension
// required for Delegated Credentials
func isCertificateValidForDelegationUsage(certificate *x509.Certificate) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(DelegatedCredentialsIdentifier) {
			return true
		}
	}
	return false
}

func (dc DelegatedCredential) marshalAndSign(cert *Certificate, scheme SignatureScheme, version uint16) ([]byte, error) {
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

	cred[publicKeyLength+7] = uint8(scheme >> 8) // hash
	cred[publicKeyLength+8] = uint8(scheme)      // signature

	signature, err := sign(cred, cert, scheme, version, publicKeyLength)

	signatureLength := len(signature)
	cred[publicKeyLength+9] = uint8(signatureLength >> 8)
	cred[publicKeyLength+10] = uint8(signatureLength)
	copy(cred[publicKeyLength+11:publicKeyLength+11+signatureLength], signature)

	return cred[0 : publicKeyLength+11+signatureLength], err
}

func unmarshalAndVerify(credentialBytes []byte, certificate *x509.Certificate, version uint16) (dc DelegatedCredential, err error) {
	dc = DelegatedCredential{}
	if !isCertificateValidForDelegationUsage(certificate) {
		return dc, fmt.Errorf("tls: delegated credentials not supported by the certificate (DelegationUsage extension missing)")
	}

	dc.ValidTime = int64(credentialBytes[0])<<24 | int64(credentialBytes[1])<<16 | int64(credentialBytes[2])<<8 | int64(credentialBytes[3])
	publicKeyLength := int(credentialBytes[4])<<16 | int(credentialBytes[5])<<8 | int(credentialBytes[6])
	PublicKeyBytes := make([]byte, publicKeyLength)
	copy(PublicKeyBytes, credentialBytes[7:7+publicKeyLength])
	dc.PublicKey, err = x509.ParsePKIXPublicKey(PublicKeyBytes)
	if err != nil {
		return dc, err
	}
	validTill := certificate.NotBefore.Add(time.Duration(dc.ValidTime) * time.Second)
	if validTill.Before(time.Now()) {
		return dc, errors.New("expired")
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
// as defined in the RFC draft
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
