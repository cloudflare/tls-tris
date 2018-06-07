package delegated_credential

import (
	"crypto"
	"crypto/tls/ext"
	"crypto/x509"
	"time"
)

// Register the DCExtension in crypto/tls/ext.
func init() {
	ext.Register(newDCExtension(ext.DelegatedCredential))
}

type dcExtension struct {
	id ext.Id
}

func newDCExtension(id ext.Id) ext.DCExtension {
	return &dcExtension{id}
}

// GetId() returns the extension ID as defined in crypto/tls/ext.
func (e dcExtension) GetId() ext.Id {
	return e.id
}

// GetPublicKey parses the serialized DC (`dc`) and returns
// the credential public key.
func (e dcExtension) GetPublicKey(dc []byte) crypto.PublicKey {
	delegatedCred, err := UnmarshalDelegatedCredential(dc)
	if err != nil {
		panic(err)
	}

	return delegatedCred.Cred.PublicKey
}

// Validate parses the serialzied DC (`dc`) and checks its validity using the
// provided certificate (`cert`), protocol version (`ver`), and the current time
// (`now`).
func (e dcExtension) Validate(
	dc []byte, cert *x509.Certificate, ver uint16, now time.Time) (bool, error) {
	delegatedCred, err := UnmarshalDelegatedCredential(dc)
	if err != nil {
		return false, err
	}

	return delegatedCred.Validate(cert, ver, now)
}
