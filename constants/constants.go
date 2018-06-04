// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package defines constants specified in the TLS standards needed by
// the base protocol as well as extensions.
package constants

const (
	VersionSSL30        = 0x0300
	VersionTLS10        = 0x0301
	VersionTLS11        = 0x0302
	VersionTLS12        = 0x0303
	VersionTLS13        = 0x0304
	VersionTLS13Draft18 = 0x7f00 | 18
	VersionTLS13Draft21 = 0x7f00 | 21
	VersionTLS13Draft22 = 0x7f00 | 22
)

const (
	PKCS1WithSHA1   = 0x0201
	PKCS1WithSHA256 = 0x0401
	PKCS1WithSHA384 = 0x0501
	PKCS1WithSHA512 = 0x0601

	PSSWithSHA256 = 0x0804
	PSSWithSHA384 = 0x0805
	PSSWithSHA512 = 0x0806

	ECDSAWithP256AndSHA256 = 0x0403
	ECDSAWithP384AndSHA384 = 0x0503
	ECDSAWithP521AndSHA512 = 0x0603

	// Legacy signature and hash algorithms for TLS 1.2.
	ECDSAWithSHA1 = 0x0203
)
