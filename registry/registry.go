// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is used to register TLS constants needed by extensions.
package registry

import "fmt"

var schemes map[string]uint16

func init() {
	schemes = make(map[string]uint16)
}

func GetSignatureScheme(key string) uint16 {
	val, ok := schemes[key]
	if !ok {
		panic(fmt.Sprintf("scheme not registered: %s", key))
	}
	return val
}

func RegisterSignatureScheme(key string, val uint16) {
	schemes[key] = val
}
