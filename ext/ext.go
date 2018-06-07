// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package defines interfaces for TLS extensions to be used by crypto/tls.
package ext

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

// Id identifies a TLS extension: see
// https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.
type Id uint16

const (
	// TODO(any) Replace with not IANA registered value
	DelegatedCredential Id = 0xff90
)

// GetName maps an extesion ID to its name.
func GetName(id Id) string {
	switch id {
	case DelegatedCredential:
		return "delegated_credential"
	default:
		panic("unknown extension id")
	}
}

// Extension is a TLS extension. Each extension offers different functionalities
// and so has a different interface; at a minimum, each extension must be able
// to identify itself.
type Extension interface {

	// GetId returns the extension identifier.
	GetId() Id
}

// DCExtension is the interface for the delegated_credential extension.
type DCExtension interface {
	Extension

	// GetPublicKey parses the DC (`dc`) and returns the credential public key.
	GetPublicKey(dc []byte) crypto.PublicKey

	// Validate parses the DC (`dc`) and checks its validity using the provided
	// certificate (`cert`), protocol version (`ver`), and the current time
	// (`now`).
	Validate(dc []byte, cert *x509.Certificate, ver uint16, now time.Time) (bool, error)
}

var extensions map[Id]Extension

func init() {
	extensions = make(map[Id]Extension)
}

// Register assigns an instance of a TLS extension implementation to its
// extension identifier, i.e., the output of `e.GetId()`. This function will
// panic if an extension has already been assigned to that identifier.
//
// This function is invoked by the package that implements the extension: see
// for example the `init()` function in crypto/tls/delegated_credential.
func Register(e Extension) {
	id := e.GetId()
	_, registered := extensions[id]
	if registered {
		panic(fmt.Errorf("%s extension is already registered", GetName(id)))
	}
	extensions[id] = e
}

// Get returns the extension instance associated with the given identifier. This
// function panics if no extension has been assigned to the identifier.
func Get(id Id) Extension {
	e, registered := extensions[id]
	if !registered {
		panic(fmt.Errorf("no %s extension registered", GetName(id)))
	}
	return e
}
