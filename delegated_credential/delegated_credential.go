// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package delegated_credential

import (
	"crypto"
	"crypto/tls"
	"crypto/tls/ext"
	"crypto/x509"
	"time"
)

func init() {
	ext.Register(newTLSExtension(ext.DelegatedCredential))
}

type ProtocolVersion uint16

const (
	MaxTTLSeconds   = 60 * 60 * 24 * 7 // Seconds
	MaxTTL          = time.Duration(MaxTTLSeconds) * time.Nanosecond
	MaxPublicKeyLen = 1 << 16 // Bytes
)

// Credential stores the public components of the credential.
//
// TODO(cjpatton) Rename DelegatedCredentialParams in the draft.
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

// NewECDSACredential generates an ECDSA key pair for the specified group and
// returns the secret key and a credential with the public key and validity
// time.
func NewCredential(
	scheme tls.SignatureScheme,
	validTime time.Duration) (crypto.PrivateKey, *Credential, error) {
	// TODO(cjpatton)
	return nil, nil, nil
}

// IsExpired returns true if and only if the credential has not expired.  The
// end of the validity interval is defined as the deleagtor certificate's
// notBefore field plus validTime seconds. This function simply checks that the
// current time is before the end of the valdity interval.
func (cred *Credential) IsExpired(start, now time.Time) bool {
	// TODO(cjpatton)
	return false
}

func (cred *Credential) HasValidTTL(start, now time.Time) bool {
	// TODO(cjpatton)
	return false
}

// Marshal encodes a credential as per the spec.
func (cred *Credential) Marshal() ([]byte, error) {
	// TODO(cjpatton)
	return nil, nil
}

// UnmarshalCredential decodes a credential.
func UnmarshalCredential(serialized []byte) (*Credential, error) {
	// TODO(cjpatton)
	return nil, nil
}

// Delegator stores the secret key of the delegator.
//
// This does not implement crypto.Signer, because this interface only works for
// PKCS1, PSS, and ECDSA signature schemes. We also want to permit use of EdDSA,
// which has a different interface.
type Delegator struct {

	// the delegation key, i.e., the signing key of the delegator.
	delegationKey crypto.PrivateKey

	// The certificate of the delegator.
	//
	// TODO(cjpatton) Determine if the delegator is meant to sign the whole
	// chain, or just the leaf. (The spec is a bit ambiguous about this.)
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
	// TODO(cjpatton)
	return nil, nil
}

// Delegate signs a credential, binding it to the provided version
//
// TODO(cjpatton) Formalize the searizlizing of the input in the spec.
func (del *Delegator) Delegate(
	cred *Credential, ver ProtocolVersion) (*DelegatedCredential, error) {
	// TODO(cjpatton)
	return nil, nil
}

// DelegatedCredential is a Credential structure signed in a given context.
type DelegatedCredential struct {
	Cred      Credential          // The credential
	Scheme    tls.SignatureScheme // The algorithm used to sign the credential
	Signature []byte              // The signature
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that it's TTL is less than 7 days. It also checks that
// certificate can be used for delegation, per the spec.
func (dc *DelegatedCredential) Validate(
	cert *x509.Certificate, ver ProtocolVersion, now time.Time) (bool, error) {
	// TODO(cjpatton)
	return false, nil
}

func (dc *DelegatedCredential) Marshal() []byte {
	// TODO(cjpatton)
	return nil
}

func Unmarshal(serialized []byte) *DelegatedCredential {
	// TODO(cjpatton)
	return nil
}

type tlsExtension struct {
	id uint16
}

func newTLSExtension(id uint16) *tlsExtension {
	return &tlsExtension{id}
}

func (ext tlsExtension) GetId() uint16 {
	return ext.id
}

func (ext tlsExtension) GetPublicKey(dc []byte) crypto.PublicKey {
	// TODO(cjpatton)
	return nil
}

func (ext tlsExtension) Validate(
	dc []byte, cert *x509.Certificate, ver uint16, now time.Time) (bool, error) {
	// TODO(cjpatton)
	return false, nil
}
