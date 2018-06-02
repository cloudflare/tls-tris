// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package delegated_credentials

import (
	"crypto"
	"crypto/x509"
)

// SignatureScheme identifies a signing algorithm as specified in the TLS 1.3
// standard.
//
// Note that this must have the same type as SignatureScheme in the crypto/tls
// package.
type SignatureScheme uint16

// Version identifies the protocol version as specified in the the TLS
// standards.
type Version uint16

const MaximumTTL = 604800 // Seconds (7 days)

// Credential stores the public componentys of the credential.
//
// TODO(cjpatton) Rename DelegatedCredentialParams in the draft.
type Credential struct {

	// Time in seconds for which the credential is valid. The TTL of the
	// credential is notBefore + validTime - currentTime, where notBefore is
	// time stamp of the delegator's certificate and currentTime is the client's
	// current time.
	validTime uint32

	// The public key of the credential.
	publicKey crypto.PublicKey
}

// TODO(cjpatton)
func (cred *Credential) Marshal() []byte {
	return nil
}

// TODO(cjpatton)
func UnmarshalCredential(serializedCred []byte) *Credential {
	return nil
}

// Delegator stores the secret key of the delegator.
//
// This does not implement crypto.Signer, because this interface only works for
// PKCS1, PSS, and ECDSA signature schemes. We also want to permit use of EdDSA,
// which has a different interface.
type Delegator struct {

	// The secret key of the delegator. This is used to sign credentials.
	privateKey crypto.PrivateKey

	// The signing algorithm corresponding to privateKey.
	Scheme SignatureScheme

	// The certificate chain of the delegator.
	//
	// TODO(cjpatton) Determine if the delegator is meant to sign the whole
	// chain, or just the leaf. (The spec is a bit ambiguous about this.)
	Cert *x509.Certificate
}

// Delegate signs a credential, binding it to the provided TLS version.
//
// TODO(cjpatton)
func (del *Delegator) Delegate(
	cred *Credential,
	version Version) (*DelegatedCredential, error) {
	return nil, nil
}

// DelegatedCredential is a Credential structure signed in a given context.
type DelegatedCredential struct {
	Cred      Credential      // The credential
	Scheme    SignatureScheme // The algorithm used to sign the credential
	Signature []byte          // The signature
}

// Verify checks that that the signature was signed by the delegator in
// possession of the secret key asoociated with cert. It also checks
// that the credential hasn't expired, and that it's TTL is less than 7 days.
//
// TODO(cjpatton)
func (dc *DelegatedCredential) Verify(
	cert *x509.Certificate,
	currentTime uint64,
	version Version) bool {
	return false
}

// TODO(cjpatton)
func (dc *DelegatedCredential) Marshal() []byte {
	return nil
}

// TODO(cjpatton)
func UnMarshalDelegatedCredential(
	serializedDelCred []byte) *DelegatedCredential {
	return nil
}
