// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux !amd64
// +build !linux !386
// +build !linux !arm
// +build !linux !arm64

package runtime

func sysargs(argc int32, argv **byte) {
}