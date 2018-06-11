// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package subcerts

import (
	"crypto/tls"
	"crypto/tls/ext"
	"testing"
	"time"
)

// Test the DCExtension interface.
func TestDCExtension(t *testing.T) {
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
		t.Fatal(err)
	}

	dc, err := delegatedCred.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	dcExt := newDCExtension(ext.DelegatedCredential)

	// Test validation.
	if v, err := dcExt.Validate(dc, cert, ver, time.Now()); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("DC is invalid, expected valid")
	}

	// Test GetPublicKey.
	testECDSAPublicKeysEqual(t,
		cred.PublicKey, dcExt.GetPublicKey(dc), tls.ECDSAWithP256AndSHA256)
}
