// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Delegated credentials for TLS
// (https://tools.ietf.org/html/draft-ietf-tls-subcerts) is an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the server may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short lived public/secret key pair
// delegated to the server by an entity trusted by the client. This allows a
// middlebox to terminate a TLS connection on behalf of the entity; for example,
// this can be used to delegate TLS termination to a reverse proxy. Credentials
// can't be revoked; in order to mitigate risk in case the middlebox is
// compromised, the credential is only valid for a short time (days, hours, or
// even minutes).
//
// BUG(cjpatton) Subcerts: Need to add support for PKCS1, PSS, and EdDSA.
// Currently delegated credentials only support ECDSA. The delegator must also
// use an ECDSA key.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	dcMaxTTLSeconds   = 60 * 60 * 24 * 7 // 7 days
	dcMaxTTL          = time.Duration(dcMaxTTLSeconds * time.Second)
	dcMaxPublicKeyLen = 1 << 16 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes
)

var errNoDelegationUsage = errors.New("certificate not authorized for delegation")

// delegationUsageId is the DelegationUsage X.509 extension OID
//
// NOTE(cjpatton) This OID is a child of Cloudflare's IANA-assigned OID.
var delegationUsageId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
//
// NOTE(cjpatton) Brendan McMillion suggests adding the delegationUsage
// extension as a flag `PermitsDelegationUsage` for the `x509.Certificate`
// structure. But we can't make this change unless tris includes crypto/x509,
// too. Once we upstream this code, we'll want to do modify x509.Certficate and
// do away with this function.
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       delegationUsageId,
		Critical: false,
		Value:    nil,
	}
}

// canDelegate returns true if a certificate can be used for delegated
// credentials.
func canDelegate(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (per the spec).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(delegationUsageId) {
			return true
		}
	}
	return false
}

// Credential structure stores the public components of a credential.
type Credential struct {
	// The amount of time for which the credential is valid. Specifically, the
	// the credential expires `ValidTime` seconds after the `notBefore` of the
	// delegation certificate. The delegator shall not issue delegated
	// credentials that are valid for more than 7 days from the current time.
	//
	// When this data structure is serialized, this value is converted to a
	// uint32 representing the duration in seconds.
	ValidTime time.Duration

	// The credential public key.
	PublicKey crypto.PublicKey

	// The signature scheme associated with the credential public key.
	//
	// NOTE This is used for bookkeeping and is not actually part of the
	// Credential structure specified in the standard.
	scheme SignatureScheme
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegator certificate's notBefore field (`start`)
// plus ValidTime seconds. This function simply checks that the current time
// (`now`) is before the end of the valdity interval.
func (cred *Credential) IsExpired(start, now time.Time) bool {
	end := start.Add(cred.ValidTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than the
// maximum permitted. This is defined by the certificate's notBefore field
// (`start`) plus the ValidTime, minus the current time (`now`).
func (cred *Credential) InvalidTTL(start, now time.Time) bool {
	return cred.ValidTime > (now.Sub(start) + dcMaxTTL).Round(time.Second)
}

// NewCredential generates a key pair for signature algorithm `scheme` and
// returns a credential with the public key and provided validity time.
func NewCredential(scheme SignatureScheme, validTime time.Duration) (*Credential, crypto.PrivateKey, error) {
	// The granularity of DC validity is seconds.
	validTime = validTime.Round(time.Second)

	// Generate a new key pair.
	var err error
	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		sk, err = ecdsa.GenerateKey(getCurve(scheme), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.(*ecdsa.PrivateKey).Public()

	default:
		return nil, nil, fmt.Errorf("unsupported signature scheme: 0x%04x", scheme)
	}

	return &Credential{validTime, pk, scheme}, sk, nil
}

// marshalSubjectPublicKeyInfo returns a DER encoded SubjectPublicKeyInfo structure
// (as defined in the X.509 standard) for the credential.
func (cred *Credential) marshalSubjectPublicKeyInfo() ([]byte, error) {
	switch cred.scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		serializedPublicKey, err := x509.MarshalPKIXPublicKey(cred.PublicKey)
		if err != nil {
			return nil, err
		}
		return serializedPublicKey, nil

	default:
		return nil, fmt.Errorf("unsupported signature scheme: 0x%04x", cred.scheme)
	}
}

// marshal encodes a credential as per the spec.
func (cred *Credential) Marshal() ([]byte, error) {
	// Write the valid_time field.
	serialized := make([]byte, 6)
	binary.BigEndian.PutUint32(serialized, uint32(cred.ValidTime/time.Second))

	// Encode the public key and assert that the encoding is no longer than 2^16
	// bytes (per the spect).
	serializedPublicKey, err := cred.marshalSubjectPublicKeyInfo()
	if err != nil {
		return nil, err
	}
	if len(serializedPublicKey) > dcMaxPublicKeyLen {
		return nil, errors.New("public key is too long")
	}

	// Write the length of the public_key field.
	binary.BigEndian.PutUint16(serialized[4:], uint16(len(serializedPublicKey)))

	// Write the public key.
	return append(serialized, serializedPublicKey...), nil
}

// unmarshalCredential decodes a credential and returns it.
func UnmarshalCredential(serialized []byte) (*Credential, error) {
	// Bytes 0-3 are the validity time field; bytes 4-6 are the length of the
	// serialized SubjectPublicKeyInfo.
	if len(serialized) < 6 {
		return nil, errors.New("credential is too short")
	}

	// Parse the validity time.
	validTime := time.Duration(binary.BigEndian.Uint32(serialized)) * time.Second

	// Parse the SubjectPublicKeyInfo.
	pk, scheme, err := unmarshalSubjectPublicKeyInfo(serialized[6:])
	if err != nil {
		return nil, err
	}

	return &Credential{validTime, pk, scheme}, nil
}

// unmarshalSubjectPublicKeyInfo parses a DER encoded SubjectPublicKeyInfo
// structure into a public key and its corresponding algorithm.
func unmarshalSubjectPublicKeyInfo(serialized []byte) (crypto.PublicKey, SignatureScheme, error) {
	PublicKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		return nil, 0, err
	}

	switch pk := PublicKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			return pk, ECDSAWithP256AndSHA256, nil
		} else if curveName == "P-384" {
			return pk, ECDSAWithP384AndSHA384, nil
		} else if curveName == "P-521" {
			return pk, ECDSAWithP521AndSHA512, nil
		} else {
			return nil, 0, fmt.Errorf("curve %s s not supported", curveName)
		}

	default:
		return nil, 0, fmt.Errorf("unsupported delgation key type: %T", pk)
	}
}

// getCredentialLen returns the number of bytes comprising the serialized
// credential that starts at the beginning of the input slice. It returns an
// error if the input is too short to contain a credential.
func getCredentialLen(serialized []byte) (int, error) {
	if len(serialized) < 6 {
		return 0, errors.New("credential is too short")
	}
	// First 4 bytes is the validity time.
	serialized = serialized[4:]

	// The next 2 bytes are the length of the serialized public key.
	serializedPublicKeyLen := int(binary.BigEndian.Uint16(serialized))
	serialized = serialized[2:]

	if len(serialized) < serializedPublicKeyLen {
		return 0, errors.New("public key of credential is too short")
	}

	return 6 + serializedPublicKeyLen, nil
}

// DelegatedCredential stores a credential and its delegation.
type DelegatedCredential struct {
	// The serialized form of the credential.
	Raw []byte

	// The credential, which contains a public and its validity time.
	Cred *Credential

	// The signature scheme used to sign the credential.
	Scheme SignatureScheme

	// The credential's delegation.
	Signature []byte
}

// Delegate signs a credential `cred` using `cert`, bindding it to the protocol
// version `vers`. It returns a delegated credential.
func Delegate(cert *Certificate, cred *Credential, vers uint16) (*DelegatedCredential, error) {
	// Parse the leaf certificate if needed.
	var err error
	if cert.Leaf == nil {
		if len(cert.Certificate[0]) == 0 {
			return nil, errors.New("missing leaf certificate")
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
	}

	// Check that the leaf certificate can be used for delegation.
	if !canDelegate(cert.Leaf) {
		return nil, errNoDelegationUsage
	}

	// Extract the delegator signature scheme from the certificate.
	var delegatorScheme SignatureScheme
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Set scheme.
		pk := sk.Public().(*ecdsa.PublicKey)
		curveName := pk.Curve.Params().Name
		certAlg := cert.Leaf.SignatureAlgorithm
		if certAlg == x509.ECDSAWithSHA256 && curveName == "P-256" {
			delegatorScheme = ECDSAWithP256AndSHA256
		} else if certAlg == x509.ECDSAWithSHA384 && curveName == "P-384" {
			delegatorScheme = ECDSAWithP384AndSHA384
		} else if certAlg == x509.ECDSAWithSHA512 && curveName == "P-521" {
			delegatorScheme = ECDSAWithP521AndSHA512
		} else {
			return nil, fmt.Errorf(
				"using curve %s for %s is not supported",
				curveName, cert.Leaf.SignatureAlgorithm)
		}
	default:
		return nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	// Prepare the credential for digital signing.
	hash := getHash(delegatorScheme)
	in, err := prepareDelegation(hash, cred, cert.Leaf.Raw, delegatorScheme, vers)
	if err != nil {
		return nil, err
	}

	// Sign the credential.
	var sig []byte
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, in, opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	return &DelegatedCredential{
		Cred:      cred,
		Scheme:    delegatorScheme,
		Signature: sig,
	}, nil
}

// NewDelegatedCredential creates a new delegated credential using `cert` for
// delegation. It generates a public/private key pair for the provided signature
// algorithm (`scheme`), validity interval (defined by `cert.Leaf.notBefore` and
// `nalidTime`), and TLS version (`vers`), and signs it using `cert.PrivateKey`.
func NewDelegatedCredential(cert *Certificate, scheme SignatureScheme, validTime time.Duration, vers uint16) (*DelegatedCredential, crypto.PrivateKey, error) {
	cred, sk, err := NewCredential(scheme, validTime)
	if err != nil {
		return nil, nil, err
	}

	dc, err := Delegate(cert, cred, vers)
	if err != nil {
		return nil, nil, err
	}
	return dc, sk, nil
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that the TTL is valid. It also checks that certificate can be
// used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, vers uint16, now time.Time) (bool, error) {
	// Check that the cert can delegate.
	if !canDelegate(cert) {
		return false, errNoDelegationUsage
	}

	if dc.Cred.IsExpired(cert.NotBefore, now) {
		return false, errors.New("credential has expired")
	}

	if dc.Cred.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("credential TTL is invalid")
	}

	// Prepare the credential for verification.
	hash := getHash(dc.Scheme)
	in, err := prepareDelegation(hash, dc.Cred, cert.Raw, dc.Scheme, vers)
	if err != nil {
		return false, err
	}

	// TODO(any) This code overlaps signficantly with verifyHandshakeSignature()
	// in ../auth.go. This should be refactored.
	switch dc.Scheme {
	case ECDSAWithP256AndSHA256,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		sig := new(ecdsaSignature)
		if _, err = asn1.Unmarshal(dc.Signature, sig); err != nil {
			return false, err
		}
		return ecdsa.Verify(pk, in, sig.R, sig.S), nil

	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Scheme)
	}
}

// Marshal encodes a DelegatedCredential structure per the spec. It also sets
// dc.Raw to the output as a side effect.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	// The credential.
	serialized, err := dc.Cred.Marshal()
	if err != nil {
		return nil, err
	}

	// The scheme.
	serializedScheme := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedScheme, uint16(dc.Scheme))
	serialized = append(serialized, serializedScheme...)

	// The signature.
	if len(dc.Signature) > dcMaxSignatureLen {
		return nil, errors.New("signature is too long")
	}
	serializedSignature := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedSignature, uint16(len(dc.Signature)))
	serializedSignature = append(serializedSignature, dc.Signature...)
	serialized = append(serialized, serializedSignature...)

	dc.Raw = serialized
	return serialized, nil
}

// UnmarshalDelegatedCredential decodes a DelegatedCredential structure.
func UnmarshalDelegatedCredential(serialized []byte) (*DelegatedCredential, error) {
	// Get the length of the serialized credential that begins at the start of
	// the input slice.
	serializedCredentialLen, err := getCredentialLen(serialized)
	if err != nil {
		return nil, err
	}

	// Parse the credential.
	cred, err := UnmarshalCredential(serialized[:serializedCredentialLen])
	if err != nil {
		return nil, err
	}

	// Parse the signature scheme.
	serialized = serialized[serializedCredentialLen:]
	if len(serialized) < 4 {
		return nil, errors.New("delegated credential is too short")
	}
	scheme := SignatureScheme(binary.BigEndian.Uint16(serialized))

	// Parse the signature length.
	serialized = serialized[2:]
	serializedSignatureLen := binary.BigEndian.Uint16(serialized)

	// Prase the signature.
	serialized = serialized[2:]
	if len(serialized) < int(serializedSignatureLen) {
		return nil, errors.New("signature of delegated credential is too short")
	}
	sig := serialized[:serializedSignatureLen]

	return &DelegatedCredential{
		Cred:      cred,
		Scheme:    scheme,
		Signature: sig,
	}, nil
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
func getCurve(scheme SignatureScheme) elliptic.Curve {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return elliptic.P256()
	case ECDSAWithP384AndSHA384:
		return elliptic.P384()
	case ECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// getHash maps the SignatureScheme to its corresponding hash function.
//
// TODO(any) This function overlaps with hashForSignatureScheme in 13.go.
func getHash(scheme SignatureScheme) crypto.Hash {
	switch scheme {
	case ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// prepareDelegation returns a hash of the message that the delegator is to
// sign. The inputs are the credential (cred), the DER-encoded delegator
// certificate (`delegatorCert`), the signature scheme of the delegator
// (`delegatorScheme`), and the protocol version (`vers`) in which the credential
// is to be used.
func prepareDelegation(hash crypto.Hash, cred *Credential, delegatorCert []byte, delegatorScheme SignatureScheme, vers uint16) ([]byte, error) {
	h := hash.New()

	// The header.
	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte("TLS, server delegated credentials"))
	h.Write([]byte{0x00})

	// The protocol version.
	var serializedVers [2]byte
	binary.BigEndian.PutUint16(serializedVers[:], uint16(vers))
	h.Write(serializedVers[:])

	// The delegation certificate.
	h.Write(delegatorCert)

	// The delegator signature scheme.
	var serializedScheme [2]byte
	binary.BigEndian.PutUint16(serializedScheme[:], uint16(delegatorScheme))
	h.Write(serializedScheme[:])

	// The credential.
	serializedCred, err := cred.Marshal()
	if err != nil {
		return nil, err
	}
	h.Write(serializedCred)

	return h.Sum(nil), nil
}
