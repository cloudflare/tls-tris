// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ext_test

import (
	_ "crypto/tls/delegated_credential"

	"crypto/tls"
	"crypto/tls/ext"

	"testing"
)

// Test that the values computed in a handshake using a delegated credential
// match the values in a handshake in which the corresponding signing key is
// used as the server's signing key.
//
// TODO(cjpatton)
func TestHandshakeWithDelegatedCredentials(t *testing.T) {
	dc := ext.Get(ext.DelegatedCredential)
	t.Log(dc.GetId())
	t.Log(tls.VersionTLS12)
}
