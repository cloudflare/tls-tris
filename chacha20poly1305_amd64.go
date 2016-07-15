// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/cipher"
	"errors"
	"strconv"
	"unsafe"
)

type chacha20Cipher struct {
	state [16]uint32
}

type chacha20poly1305 struct {
	*chacha20Cipher
}

//go:noescape
func chacha20Poly1305Open(dst []byte, key []uint32, src, ad []byte) bool

//go:noescape
func chacha20Poly1305Seal(dst []byte, key []uint32, src, ad []byte)

type KeySizeError int
type IVSizeError int

func (k KeySizeError) Error() string {
	return "crypto/chacha20poly1305: invalid key size " + strconv.Itoa(int(k))
}

func (i IVSizeError) Error() string {
	return "crypto/chacha20poly1305: invalid iv size " + strconv.Itoa(int(i))
}

func u8tou32(in []byte) uint32 {
	if supportsUnaligned {
		return *(*uint32)(unsafe.Pointer(&in[0]))
	} else {
		return uint32(in[0]) ^ uint32(in[1])<<8 ^ uint32(in[2])<<16 ^ uint32(in[3])<<24
	}
}

func newChacha(key []byte) (*chacha20Cipher, error) {
	k := len(key)

	if k != 32 {
		return nil, KeySizeError(k)
	}

	c := chacha20Cipher{state: [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		u8tou32(key[0:4]), u8tou32(key[4:8]), u8tou32(key[8:12]), u8tou32(key[12:16]),
		u8tou32(key[16:20]), u8tou32(key[20:24]), u8tou32(key[24:28]), u8tou32(key[28:32]),
		0, 0, 0, 0},
	}

	return &c, nil
}

func (c *chacha20Cipher) setIV(iv []byte, ctr uint32) error {
	i := len(iv)

	if i != 12 {
		return IVSizeError(i)
	}

	c.state[12] = ctr
	c.state[13] = u8tou32(iv[0:4])
	c.state[14] = u8tou32(iv[4:8])
	c.state[15] = u8tou32(iv[8:12])

	return nil
}

func NewChachaPoly(key []byte) (cipher.AEAD, error) {
	c, err := newChacha(key)
	if err != nil {
		return nil, err
	}

	ret := &chacha20poly1305{c}
	return ret, nil
}

func (cp *chacha20poly1305) NonceSize() int {
	return 12
}

func (cp *chacha20poly1305) Overhead() int {
	return 16
}

func (cp *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	if additionalData == nil {
		additionalData = make([]byte, 0)
	}

	if plaintext == nil {
		plaintext = make([]byte, 0)
	}

	ret, out := sliceForAppend(dst, len(plaintext)+16)
	chacha20Poly1305Seal(out[:], cp.state[:], plaintext, additionalData)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (cp *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var err error

	if err = cp.setIV(nonce, 0); err != nil {
		panic("chacha20poly1305: incorrect nonce length given to ChaCha20-Poly1305")
	}

	if len(ciphertext) < 16 {
		return nil, errOpen
	}

	if additionalData == nil {
		additionalData = make([]byte, 0)
	}

	ciphertext = ciphertext[:len(ciphertext)-16]
	ret, out := sliceForAppend(dst, len(ciphertext))
	if chacha20Poly1305Open(out, cp.state[:], ciphertext, additionalData) != true {
		return nil, errOpen
	}

	return ret, nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
