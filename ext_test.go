// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	delegated "crypto/tls/ext/delegated_credentials"
	"testing"
)

// Test that the values computed in a handshake using a delegated credential
// match the vauless in a handshake in which the corresponding signing key is
// used as the server's signing key.
//
// TODO(cjpatton)
func TestHandshakeWithDelegatedCredentials(t *testing.T) {
	_ = &delegated.DelegatedCredential{}
	t.Skip("delegated_credentials is not implemented")
}
