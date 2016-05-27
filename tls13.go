package tls

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"

	"golang.org/x/crypto/hkdf"
)

func (hs *serverHandshakeState) doTLS13Handshake() error {
	config := hs.c.config
	c := hs.c

	var ks *keyShare
	for i, keyShare := range hs.clientHello.keyShares {
		for _, otherKS := range hs.clientHello.keyShares[i+1:] {
			if keyShare.group == otherKS.group {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: duplicate key share for the same type")
			}
		}
		supported := false
		for _, supportedCurve := range hs.clientHello.supportedCurves {
			if supportedCurve == keyShare.group {
				supported = true
				break
			}
		}
		if !supported {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: received key share for unsupported curve")
		}
		if ks == nil {
			for _, curveID := range config.curvePreferences() {
				if curveID == keyShare.group {
					ks = &keyShare
					break
				}
			}
		}
	}
	if ks == nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: HelloRetryRequest not implemented") // TODO(filippo)
	}

	curve, privateKey, serverKS, err := config.generateKeyShare(ks.group)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello.keyShare = serverKS

	ES := deriveECDHESecret(curve, ks.data, privateKey)
	if ES == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}
	println("ES:")
	println(hex.Dump(ES))

	println("xES:")
	h := hmac.New(sha256.New, make([]byte, sha256.Size)) //TODO(filippo)
	h.Write(ES)
	println(hex.Dump(h.Sum(nil)))

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	println("Hash:")
	println(hex.Dump(hs.finishedHash.Sum()))
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	handshakeCtxt := hs.finishedHash.Sum()
	cKey := HKDFExpandLabel(sha256.New, nil, ES, handshakeCtxt, "handshake key expansion, client write key", 16)
	println("client write key:")
	println(hex.Dump(cKey))
	cIV := HKDFExpandLabel(sha256.New, nil, ES, handshakeCtxt, "handshake key expansion, client write iv", 12) // Lowercase because NSS
	println("Client Write IV:")
	println(hex.Dump(cIV))
	sKey := HKDFExpandLabel(sha256.New, nil, ES, handshakeCtxt, "handshake key expansion, server write key", 16)
	println("Server Write Key:")
	println(hex.Dump(sKey))
	sIV := HKDFExpandLabel(sha256.New, nil, ES, handshakeCtxt, "handshake key expansion, server write iv", 12) // Lowercase because NSS
	println("Server Write IV:")
	println(hex.Dump(sIV))

	clientCipher := aeadTLS13(cKey, cIV)
	serverCipher := aeadTLS13(sKey, sIV)

	c.in.prepareCipherSpec(c.vers, clientCipher, nil)
	c.out.prepareCipherSpec(c.vers, serverCipher, nil)
	c.in.changeCipherSpec()
	c.out.changeCipherSpec()

	hs.finishedHash.Write(hs.hello.marshalEncExtensions())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshalEncExtensions()); err != nil {
		return err
	}

	certMsg := &certificateMsg{
		requestContext: true,
		certificates:   hs.cert.Certificate,
	}
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	sigType := signatureRSA
	if hs.suite.flags&suiteECDSA != 0 {
		sigType = signatureECDSA
	}
	hashType, err := pickTLS12HashForSignature(sigType, hs.clientHello.signatureAndHashes)
	hash := hs.finishedHash.Sum()
	println("Finished Hash:")
	println(hex.Dump(hash))
	paddedHash := padDigitallySigned("TLS 1.3, server CertificateVerify", hash)
	hashPaddedHash := sha256.Sum256(paddedHash)
	println("Hash of Padded Hash:")
	println(hex.Dump(hashPaddedHash[:]))

	signature, err := hs.cert.PrivateKey.(crypto.Signer).Sign(config.rand(), hashPaddedHash[:], nil)
	if err != nil {
		return err
	}

	verifyMsg := &certificateVerifyMsg{
		hasSignatureAndHash: true,
		signatureAndHash: signatureAndHash{
			hash: hashType, signature: sigType,
		},
		signature: signature,
	}
	hs.finishedHash.Write(verifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, verifyMsg.marshal()); err != nil {
		return err
	}
	mSS := HKDFExpandLabel(sha256.New, nil, ES, hs.finishedHash.Sum(), "expanded static secret", sha256.Size)
	println("mSS:")
	println(hex.Dump(mSS))
	mES := HKDFExpandLabel(sha256.New, nil, ES, hs.finishedHash.Sum(), "expanded ephemeral secret", sha256.Size)
	println("mES:")
	println(hex.Dump(mES))
	serverFinishedKey := HKDFExpandLabel(sha256.New, mSS, mES, nil, "server finished", sha256.Size)
	println("Server Finished Key:")
	println(hex.Dump(serverFinishedKey))
	h = hmac.New(sha256.New, serverFinishedKey)
	h.Write(hs.finishedHash.Sum())
	verifyData := h.Sum(nil)
	finishedMsg := &finishedMsg{
		verifyData: verifyData,
	}
	if _, err := c.writeRecord(recordTypeHandshake, finishedMsg.marshal()); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	return errors.New("WIP")
}

func padDigitallySigned(context string, data []byte) []byte {
	padding := bytes.Repeat([]byte{32}, 64)
	padding = append(padding, context...)
	padding = append(padding, 0)
	padding = append(padding, data...)
	return padding
}

func (c *Config) generateKeyShare(curveID CurveID) (elliptic.Curve, []byte, *keyShare, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, nil, nil, errors.New("tls: preferredCurves includes unsupported curve")
	}

	privateKey, x, y, err := elliptic.GenerateKey(curve, c.rand())
	if err != nil {
		return nil, nil, nil, err
	}
	ecdhePublic := elliptic.Marshal(curve, x, y)

	data := make([]byte, 1+len(ecdhePublic))
	data[0] = byte(len(ecdhePublic))
	copy(data[1:], ecdhePublic)
	return curve, privateKey, &keyShare{group: curveID, data: data}, nil
}

func deriveECDHESecret(curve elliptic.Curve, ks, pk []byte) []byte {
	if len(ks) < 1 {
		return nil
	}
	x, y := elliptic.Unmarshal(curve, ks[1:])
	if x == nil {
		return nil
	}
	x1, _ := curve.ScalarMult(x, y, pk)
	x1Bytes := x1.Bytes()
	curveSize := curve.Params().P.BitLen() / 8
	if len(x1Bytes) != curveSize {
		buf := make([]byte, curveSize)
		copy(buf[curveSize-len(x1Bytes):], x1Bytes)
		x1Bytes = buf
	}
	return x1Bytes
}

func HKDFExpandLabel(hash func() hash.Hash, salt, secret, hashValue []byte, label string, L int) []byte {
	hkdfLabel := make([]byte, 4+len("TLS 1.3, ")+len(label)+len(hashValue))
	hkdfLabel[0] = byte(L >> 8)
	hkdfLabel[1] = byte(L)
	hkdfLabel[2] = byte(len("TLS 1.3, ") + len(label))
	copy(hkdfLabel[3:], "TLS 1.3, ")
	z := hkdfLabel[3+len("TLS 1.3, "):]
	copy(z, label)
	z = z[len(label):]
	z[0] = byte(len(hashValue))
	copy(z[1:], hashValue)

	println("Label:")
	println(hex.Dump(hkdfLabel))

	res := make([]byte, L)
	if salt == nil {
		salt = make([]byte, hash().Size())
	}
	hkdf.New(hash, secret, salt, hkdfLabel).Read(res)
	return res
}

type tls13AEAD struct {
	aead cipher.AEAD
	IV   []byte
}

func aeadTLS13(key, IV []byte) *tls13AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	return &tls13AEAD{aead, IV}
}
