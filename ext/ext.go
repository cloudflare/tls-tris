// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package defines an interface for crypto/tls/delegated_credential to
// be used by crypto/tls.
package ext

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"
)

const (
	// TODO(amu) Replace with not IANA registered value
	DelegatedCredential uint16 = 0xff90
)

// TODO
func GetName(id uint16) string {
	switch id {
	case DelegatedCredential:
		return "delegated_credential"
	default:
		panic("unknown extension id")
	}
}

// TODO
type Extension interface {
	GetId() uint16
}

// TODO
type DCExtension interface {
	Extension
	GetPublicKey(dc []byte) crypto.PublicKey
	Validate(dc []byte, cert *x509.Certificate, ver uint16, now time.Time) (bool, error)
}

var extensions map[uint16]Extension

func init() {
	extensions = make(map[uint16]Extension)
}

// TODO
func Register(e Extension) {
	id := e.GetId()
	_, registered := extensions[id]
	if registered {
		panic(fmt.Errorf("%s extension is already registered", GetName(id)))
	}
	extensions[id] = e
}

func Get(id uint16) Extension {
	e, registered := extensions[id]
	if !registered {
		panic(fmt.Errorf("no %s extension registered", GetName(id)))
	}
	return e
}
