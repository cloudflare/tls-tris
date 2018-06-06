package delegated_credential

import (
	"crypto"
	"crypto/tls/ext"
	"crypto/x509"
	"time"
)

func init() {
	ext.Register(newTLSExtension(ext.DelegatedCredential))
}

type tlsExtension struct {
	id uint16
}

func newTLSExtension(id uint16) *tlsExtension {
	return &tlsExtension{id}
}

func (ext tlsExtension) GetId() uint16 {
	return ext.id
}

func (ext tlsExtension) GetPublicKey(dc []byte) crypto.PublicKey {
	// TODO(cjpatton)
	return nil
}

func (ext tlsExtension) Validate(
	dc []byte, cert *x509.Certificate, ver uint16, now time.Time) (bool, error) {
	// TODO(cjpatton)
	return false, nil
}
