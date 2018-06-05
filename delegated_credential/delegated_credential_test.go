package delegated_credential_test

import (
	_ "crypto/tls"
	deleg "crypto/tls/delegated_credential"

	"testing"
)

// TODO(cjpatton)
func TestDelegateVerify(t *testing.T) {
	t.Log(deleg.RequireECDSAWithP256AndSHA256())
}
