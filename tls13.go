package tls

import (
	"crypto/elliptic"
	"errors"
)

func (c *Config) generateKeyShare(curveID CurveID) (keyShare, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return keyShare{}, errors.New("tls: preferredCurves includes unsupported curve")
	}

	privateKey, x, y, err := elliptic.GenerateKey(curve, c.rand())
	if err != nil {
		return keyShare{}, err
	}
	ecdhePublic := elliptic.Marshal(curve, x, y)
	_, _ = curve, privateKey

	data := make([]byte, 1+len(ecdhePublic))
	data[0] = byte(len(ecdhePublic))
	copy(data[1:], ecdhePublic)
	return keyShare{group: curveID, data: data}, nil
}
