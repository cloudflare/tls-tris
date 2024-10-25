// Standalone utility to generate ESNI keys.
// Can be run independently of tris.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
)

// Internal definitions, copied from common.go and esni.go

type keyShare struct {
	group tls.CurveID
	data  []byte
}

const esniKeysVersionDraft01 uint16 = 0xff01

func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// ESNIKeys structure that is exposed through DNS.
type ESNIKeys struct {
	version  uint16
	checksum [4]uint8
	// (Draft -03 introduces "public_name" here)
	keys         []keyShare // 16-bit vector length
	cipherSuites []uint16   // 16-bit vector length
	paddedLength uint16
	notBefore    uint64
	notAfter     uint64
	extensions   []byte // 16-bit vector length. No extensions are defined in draft -01
}

func (k *ESNIKeys) serialize() []byte {
	var b cryptobyte.Builder
	b.AddUint16(k.version)
	b.AddBytes(k.checksum[:])
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range k.keys {
			b.AddUint16(uint16(ks.group))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.data)
			})
		}
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cs := range k.cipherSuites {
			b.AddUint16(cs)
		}
	})
	b.AddUint16(k.paddedLength)
	addUint64(&b, k.notBefore)
	addUint64(&b, k.notAfter)
	// No extensions are defined in the initial draft.
	b.AddUint16(0)
	// Should always succeed as we use simple types only.
	return b.BytesOrPanic()
}

func generateX25519() ([]byte, keyShare) {
	var scalar, public [32]byte
	if _, err := rand.Read(scalar[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&public, &scalar)
	ks := keyShare{
		group: tls.X25519,
		data:  public[:],
	}
	return scalar[:], ks
}

// Creates a new ESNIKeys structure with a new semi-static key share.
// Returns the private key and a new ESNIKeys structure.
func NewESNIKeys(validity time.Duration) ([]byte, *ESNIKeys) {
	serverPrivate, serverKS := generateX25519()
	notBefore := time.Now()
	notAfter := notBefore.Add(validity)
	k := &ESNIKeys{
		version:      esniKeysVersionDraft01,
		keys:         []keyShare{serverKS},
		cipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
		// draft-ietf-tls-esni-01: "If the server supports wildcard names, it SHOULD set this value to 260."
		paddedLength: 260,
		notBefore:    uint64(notBefore.Unix()),
		notAfter:     uint64(notAfter.Unix()),
	}
	data := k.serialize()
	hash := sha256.New()
	hash.Write(data[:2]) // version
	hash.Write([]byte{0, 0, 0, 0})
	hash.Write(data[6:]) // fields after checksum
	copy(k.checksum[:], hash.Sum(nil)[:4])
	return serverPrivate, k
}

func main() {
	var esniKeysFile, esniPrivateFile string
	var validity time.Duration
	flag.StringVar(&esniKeysFile, "esni-keys-file", "", "Write base64-encoded ESNI keys to file instead of stdout")
	flag.StringVar(&esniPrivateFile, "esni-private-file", "", "Write ESNI private key to file instead of stdout")
	flag.DurationVar(&validity, "validity", 24*time.Hour, "Validity period of the keys")
	flag.Parse()

	serverPrivate, k := NewESNIKeys(validity)
	esniBase64 := base64.StdEncoding.EncodeToString(k.serialize())
	if esniKeysFile == "" {
		// draft -01 uses a TXT record instead of a dedicated RR.
		fmt.Printf("_esni TXT record: %s\n", esniBase64)
	} else {
		err := ioutil.WriteFile(esniKeysFile, []byte(esniBase64+"\n"), 0644)
		if err != nil {
			log.Fatalf("Failed to write %s: %s", esniKeysFile, err)
		}
	}
	if esniPrivateFile == "" {
		fmt.Printf("ESNI private key: %x\n", serverPrivate)
	} else {
		err := ioutil.WriteFile(esniPrivateFile, serverPrivate, 0600)
		if err != nil {
			log.Fatalf("Failed to write %s: %s", esniPrivateFile, err)
		}
	}
}
