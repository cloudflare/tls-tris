// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Delegated credentials for TLS
// (https://tools.ietf.org/html/draft-ietf-tls-subcerts) is an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the servery may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short lived public/secret key pair
// delegated to the server by an entity trusted by the client. This allows a
// middlebox to terminate a TLS connection on behalf of the entity; for example,
// this can be used to delegate TLS termination to a reverse proxy. Credentials
// can't be revoked; in order to mitigate risk in case the middlebox is
// compromised, the credential is only valid for a short time (days, hours, or
// even minutes).
//
// This package implements the functionalities needed for the
// delegated_credential extension for TLS, as well as provisioning delegated
// credentials for use in the protocol. It implements the DCExtension interface
// defined in crypto/tls/ext. To use the extension in TLS, you must import this
// package to register the extension. Your imports will look something like
// this:
//
// 		import (
//			_ "crypto/tls/delegated_credential" // Register the extension
//
//			"crypto/tls/ext"
//		)
//
// To access the interface, do
//
// 		dc := ext.Extension(ext.DelegatedCredential)
//
// BUG(cjpatton) Need to add support for PKCS1, PSS, and EdDSA. Currently
// delegated credentials only support ECDSA. The delegator must also use an
// ECDSA key.
package subcerts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"
)

const (
	MaxValidTimeSeconds = 60 * 60 * 24 * 7 // 7 days
	MaxValidTime        = time.Duration(MaxValidTimeSeconds * time.Second)
	MaxPublicKeyLen     = 1 << 16 // Bytes
	MaxSignatureLen     = 1 << 16 // Bytes
)

var errNoDelegationUsage = errors.New("certificate not authorized for delegation")

// DelegationUsageId is the DelegationUsage X.509 extension OID
//
// TODO(any) Replace with the real OID. This value is temporary.
var DelegationUsageId = asn1.ObjectIdentifier{2, 5, 29, 99}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       DelegationUsageId,
		Critical: false,
		Value:    nil,
	}
}

// CanDelegate checks that a certificate can be used for delegated credentials
// and reuturns nil if it can. Otherwise it returns an error conveying the
// reason why the certificate can't be used.
func CanDelegate(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (per the spec).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(DelegationUsageId) {
			return true
		}
	}
	return false
}

// Credential stores the public components of a credential.
type Credential struct {

	// Time in nonsecnds for which the credential is valid. When this data
	// structure is serialized, this value is converted to a uint32 representing
	// the duration in seconds.
	ValidTime time.Duration

	// The public key of the credential.
	PublicKey crypto.PublicKey

	// The signature scheme corresponding to PublicKey.
	scheme tls.SignatureScheme
}

// NewCredential generates a public/secret key pair for the given singature scheme, creates a
// credential with the public key and given validity period, and returns the
// secret key and the credential.
func NewCredential(
	scheme tls.SignatureScheme,
	validTime time.Duration) (crypto.PrivateKey, *Credential, error) {

	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch scheme {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:

		sk, err := ecdsa.GenerateKey(getCurve(scheme), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.Public()

	default:
		return nil, nil, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", scheme)
	}

	return sk, &Credential{validTime, pk, scheme}, nil
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the deleagtor certificate's notBefore field (`start`)
// plus ValidTime seconds. This function simply checks that the current time
// (`now`) is before the end of the valdity interval.
func (cred *Credential) IsExpired(start, now time.Time) bool {
	end := start.UTC().Add(cred.ValidTime)
	return !now.UTC().Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than the
// maximum permitted. This is defined by the certificate's notBefore field
// (`start`) plus the ValidTime, minus the current time (`now`).
func (cred *Credential) InvalidTTL(start, now time.Time) bool {
	end := start.UTC().Add(cred.ValidTime - 1)
	maxEnd := start.UTC().Add(MaxValidTime)
	return !end.Before(maxEnd)
}

// marshalSubjectPublicKeyInfo returns a DER encoded SubjectPublicKeyInfo structure
// (as defined in the X.509 standard) for the credential.
func (cred *Credential) marshalSubjectPublicKeyInfo() ([]byte, error) {
	switch cred.scheme {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:

		serializedPublicKey, err := x509.MarshalPKIXPublicKey(cred.PublicKey)
		if err != nil {
			return nil, err
		}
		return serializedPublicKey, nil

	default:
		return nil, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", cred.scheme)
	}
}

// unmarshalSubjectPublicKeyInfo parses a DER encoded SubjectPublicKeyINfo
// structure into a public key and its corresponding algorithm.
func unmarshalSubjectPublicKeyInfo(
	serialized []byte) (crypto.PublicKey, tls.SignatureScheme, error) {

	publicKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		return nil, 0, err
	}

	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:

		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			return pk, tls.ECDSAWithP256AndSHA256, nil
		} else if curveName == "P-384" {
			return pk, tls.ECDSAWithP384AndSHA384, nil
		} else if curveName == "P-521" {
			return pk, tls.ECDSAWithP521AndSHA512, nil
		} else {
			return nil, 0, fmt.Errorf("curve %s s not supported", curveName)
		}

	default:
		return nil, 0, fmt.Errorf(
			"unsupported delgation key type: %s", reflect.TypeOf(pk))
	}
}

// Marshal encodes a credential as per the spec.
func (cred *Credential) Marshal() ([]byte, error) {
	// Write the valid_time field.
	serialized := make([]byte, 6)
	binary.BigEndian.PutUint32(serialized, uint32(cred.ValidTime/time.Second))

	// Encode the public key.
	serializedPublicKey, err := cred.marshalSubjectPublicKeyInfo()
	if err != nil {
		return nil, err
	}

	// Assert that the public key is no longer than 2^16 bytes per the spec.
	if len(serializedPublicKey) > MaxPublicKeyLen {
		return nil, errors.New("public key is too long")
	}

	// Write the length of the public_key field.
	binary.BigEndian.PutUint16(serialized[4:], uint16(len(serializedPublicKey)))

	// Write the public key.
	return append(serialized, serializedPublicKey...), nil
}

// UnmarshalCredential decodes a credential and returns it.
func UnmarshalCredential(serialized []byte) (*Credential, error) {

	// Check that the serialized credential is long enough and compute the
	// length of the serialized public key.
	serializedPublicKeyLen, err := getCredentialLen(serialized)
	if err != nil {
		return nil, err
	}
	serializedPublicKeyLen -= 6

	// Parse the validity time.
	validTime := time.Duration(binary.BigEndian.Uint32(serialized)) * time.Second

	// Parse the SubjectPublicKeyInfo.
	serialized = serialized[6:]
	pk, scheme, err := unmarshalSubjectPublicKeyInfo(serialized)
	if err != nil {
		return nil, err
	}

	return &Credential{validTime, pk, scheme}, nil
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

// Delegator stores the secret key of the delegator.
//
// This does not implement crypto.Signer, because the semantics of sigining is
// somewhat different. In particular, the delegator binds the credential to the
// protocol, the signature scheme of the delegator, and the certificate of the
// delegator.
type Delegator struct {

	// the delegation key, i.e., the signing key of the delegator.
	delegationKey crypto.PrivateKey

	// The certificate of the delegator.
	cert *x509.Certificate

	// The signing algorithm of the delegation key. This must be a uint16 as per
	// the TLS 1.3 spec.
	scheme tls.SignatureScheme
}

// NewDelegator initializes the delegator state using the delagation key and the
// corresponding certificate cert. It ensures that the public key corresponding
// to delegationKey is the same public key as in cert. It also ensures that
// certificate can be used for delegation, as per the spec.
func NewDelegator(
	delegationKey crypto.PrivateKey, cert *x509.Certificate) (*Delegator, error) {

	if !CanDelegate(cert) {
		return nil, errNoDelegationUsage
	}

	// Check that the public key corresponding to secretKey matches the
	// certificate and extract the signature schemf rom the certificate.
	var scheme tls.SignatureScheme
	switch sk := delegationKey.(type) {
	case *ecdsa.PrivateKey:

		// Check that the certificate public key is an ECDSA key.
		if reflect.TypeOf(cert.PublicKey) != reflect.TypeOf(sk.Public()) {
			return nil, errors.New("public-key type mismatch")
		}
		pk := sk.Public().(*ecdsa.PublicKey)

		// Check that the public keys match.
		if reflect.TypeOf(cert.PublicKey.(*ecdsa.PublicKey).Curve) !=
			reflect.TypeOf(pk.Curve) {
			return nil, errors.New("public-key group mismatch")
		}
		if cert.PublicKey.(*ecdsa.PublicKey).X.Cmp(pk.X) != 0 {
			return nil, errors.New("public-key x-coordinate mismatch")
		}
		if cert.PublicKey.(*ecdsa.PublicKey).Y.Cmp(pk.Y) != 0 {
			return nil, errors.New("public-key y-corrdinate mismatch")
		}

		// Set scheme.
		curveName := pk.Curve.Params().Name
		certAlg := cert.SignatureAlgorithm
		if certAlg == x509.ECDSAWithSHA256 && curveName == "P-256" {
			scheme = tls.ECDSAWithP256AndSHA256
		} else if certAlg == x509.ECDSAWithSHA384 && curveName == "P-384" {
			scheme = tls.ECDSAWithP384AndSHA384
		} else if certAlg == x509.ECDSAWithSHA512 && curveName == "P-521" {
			scheme = tls.ECDSAWithP521AndSHA512
		} else {
			return nil, fmt.Errorf(
				"using curve %s for %s is not supported",
				curveName, cert.SignatureAlgorithm)
		}

	default:
		return nil, fmt.Errorf(
			"unsupported delgation key type: %s", reflect.TypeOf(sk))
	}

	return &Delegator{delegationKey, cert, scheme}, nil
}

// Delegate signs a credential, binding it to the provided protocol version
// (`ver`).
func (del *Delegator) Delegate(
	cred *Credential, ver uint16) (*DelegatedCredential, error) {

	// Prepare the credential for digital signing.
	hash := getHash(del.scheme)
	in, err := prepareDigitallySigned(hash, cred, del.cert.Raw, del.scheme, ver)
	if err != nil {
		return nil, err
	}

	// Sign the creential.
	var sig []byte
	switch sk := del.delegationKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, in, opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf(
			"unsupported delgation key type: %s", reflect.TypeOf(sk))
	}

	return &DelegatedCredential{*cred, del.scheme, sig}, nil
}

// DelegatedCredential is a Credential structure signed by a delegator.
type DelegatedCredential struct {
	Cred      Credential          // The credential
	Scheme    tls.SignatureScheme // The algorithm used to sign the credential
	Signature []byte              // The signature
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that the TTL is valid. It also checks that certificate can be
// used for delegation.
func (dc *DelegatedCredential) Validate(
	cert *x509.Certificate, ver uint16, now time.Time) (bool, error) {

	if !CanDelegate(cert) {
		return false, errNoDelegationUsage
	}

	if dc.Cred.IsExpired(cert.NotBefore, now) {
		return false, errors.New("credential has expired")
	}

	if dc.Cred.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("credential TTL is invalid")
	}

	// Prepare the crednetial for verification.
	hash := getHash(dc.Scheme)
	in, err := prepareDigitallySigned(hash, &dc.Cred, cert.Raw, dc.Scheme, ver)
	if err != nil {
		return false, err
	}

	// NOTE(cjpatton) This code overlaps signficantly with
	// verifyHandshakeSignature() in ../auth.go.
	switch dc.Scheme {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:

		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		sig := new(ecdsaSignature)
		if _, err = asn1.Unmarshal(dc.Signature, sig); err != nil {
			return false, err
		}
		if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
			return false, errors.New("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pk, in, sig.R, sig.S) {
			return false, errors.New("ECDSA verification failure")
		}
		return true, nil

	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Scheme)
	}

	return false, nil
}

// NOTE(cjpatton) This is copied from crypto/tls (common.go).
type ecdsaSignature struct {
	R, S *big.Int
}

// Marshal encodes a DelegatedCredential structure per the spec.
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
	if len(dc.Signature) > MaxSignatureLen {
		return nil, errors.New("signature is too long")
	}
	serializedSignature := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedSignature, uint16(len(dc.Signature)))
	serializedSignature = append(serializedSignature, dc.Signature...)
	serialized = append(serialized, serializedSignature...)

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
	scheme := tls.SignatureScheme(binary.BigEndian.Uint16(serialized))

	// Parse the signature length.
	serialized = serialized[2:]
	serializedSignatureLen := binary.BigEndian.Uint16(serialized)

	// Prase the signature.
	serialized = serialized[2:]
	if len(serialized) < int(serializedSignatureLen) {
		return nil, errors.New("signature of delegated credential is too short")
	}
	sig := serialized[:serializedSignatureLen]

	return &DelegatedCredential{*cred, scheme, sig}, nil
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
func getCurve(scheme tls.SignatureScheme) elliptic.Curve {
	switch scheme {
	case tls.ECDSAWithP256AndSHA256:
		return elliptic.P256()
	case tls.ECDSAWithP384AndSHA384:
		return elliptic.P384()
	case tls.ECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// getHash maps the SignatureScheme to its corresponding hash function.
func getHash(scheme tls.SignatureScheme) crypto.Hash {
	switch scheme {
	case tls.ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case tls.ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case tls.ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// prepareDigitallySigned returns a hash of the message that the delegator is to
// sign. The inputs are the credential (cred), the DER-encoded delegator
// certificate (`delegatorCert`), the signature scheme of the delegator
// (`delegatorScheme`), and the protocol version (`ver`) in which the credential
// is to be used.
func prepareDigitallySigned(
	hash crypto.Hash,
	cred *Credential,
	delegatorCert []byte,
	delegatorScheme tls.SignatureScheme,
	ver uint16) ([]byte, error) {

	h := hash.New()

	// The header.
	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte("TLS, server delegated credentials"))
	h.Write([]byte{0x00})

	// The protocol version.
	serializedVer := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedVer, uint16(ver))
	h.Write(serializedVer)

	// The delegation certificate.
	h.Write(delegatorCert)

	// The delegator signature scheme.
	serializedScheme := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedScheme, uint16(delegatorScheme))
	h.Write(serializedScheme)

	// The credential.
	serializedCred, err := cred.Marshal()
	if err != nil {
		return nil, err
	}
	h.Write(serializedCred)

	return h.Sum(nil), nil
}
