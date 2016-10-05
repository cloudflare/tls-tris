package tls

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

func (hs *serverHandshakeState) doTLS13Handshake() error {
	config := hs.c.config
	c := hs.c

	// Group choice logic
	//
	// When picking the group for the handshake, priority is given to groups
	// that the client provided a keyShare for, so to avoid a round-trip.
	// After that the order of CurvePreferences is respected.
	//
	// Conveniently, this logic never affects the cipher suite choice, as
	// crypto/tls only supports ECDHE.

	var ks *keyShare
	for _, curveID := range config.curvePreferences() {
		for _, keyShare := range hs.clientHello.keyShares {
			if curveID == keyShare.group {
				ks = &keyShare
				break
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

	hash := crypto.SHA256
	if hs.suite.flags&suiteSHA384 != 0 {
		hash = crypto.SHA384
	}

	resCtxHash := hash.New()
	resCtxHash.Write(make([]byte, hash.Size()))
	resCtx := resCtxHash.Sum(nil)

	ecdheSecret := deriveECDHESecret(curve, ks.data, privateKey)
	if ecdheSecret == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}

	hs.c.cipherSuite, hs.hello.cipherSuite = hs.suite.id, hs.suite.id
	hs.c.clientHello = hs.clientHello.marshal()

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	clientLabel, serverLabel := "", ""
	clientExpandLabel, serverExpandLabel := "client write ", "server write "
	if hs.hello.realVers >= 0x7f00+16 {
		clientLabel, serverLabel = "client ", "server "
		clientExpandLabel, serverExpandLabel = "", ""
	}

	earlySecret := hkdfExtract(hash, nil, nil)
	handshakeSecret := hkdfExtract(hash, ecdheSecret, earlySecret)

	handshakeCtx := hs.finishedHash.Sum()

	cHandshakeTS := deriveSecret(hash, handshakeSecret, handshakeCtx, clientLabel+"handshake traffic secret")
	cKey := hkdfExpandLabel(hash, cHandshakeTS, nil, "handshake key expansion, "+clientExpandLabel+"key", hs.suite.keyLen)
	cIV := hkdfExpandLabel(hash, cHandshakeTS, nil, "handshake key expansion, "+clientExpandLabel+"iv", 12)
	sHandshakeTS := deriveSecret(hash, handshakeSecret, handshakeCtx, serverLabel+"handshake traffic secret")
	sKey := hkdfExpandLabel(hash, sHandshakeTS, nil, "handshake key expansion, "+serverExpandLabel+"key", hs.suite.keyLen)
	sIV := hkdfExpandLabel(hash, sHandshakeTS, nil, "handshake key expansion, "+serverExpandLabel+"iv", 12)

	var aead func([]byte, []byte) cipher.AEAD
	if hs.suite.id == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 || hs.suite.id == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ||
		hs.suite.id == TLS_CHACHA20_POLY1305_SHA256 {
		aead = aeadChaCha20Poly1305
	} else {
		aead = aeadAESGCM13
	}

	clientCipher := aead(cKey, cIV)
	serverCipher := aead(sKey, sIV)

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

	// TODO(filippo): need a new, proper type for 1.3 SignatureScheme

	sigScheme, sigHash, err := hs.selectTLS13SignatureScheme()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	opts := crypto.SignerOpts(sigHash)
	if sigScheme.hash == 0x07 && sigScheme.signature <= 0x02 ||
		sigScheme.hash == 0x08 && sigScheme.signature <= 0x06 { // rsa_pss_*
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}

	hashedData := append(hs.finishedHash.Sum(), resCtx...)
	toSign := prepareDigitallySigned(sigHash, "TLS 1.3, server CertificateVerify", hashedData)
	signature, err := hs.cert.PrivateKey.(crypto.Signer).Sign(config.rand(), toSign[:], opts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	verifyMsg := &certificateVerifyMsg{
		hasSignatureAndHash: true,
		signatureAndHash:    sigScheme,
		signature:           signature,
	}
	hs.finishedHash.Write(verifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, verifyMsg.marshal()); err != nil {
		return err
	}

	clientFinishedLabel, serverFinishedLabel := "client ", "server "
	if hs.hello.realVers >= 0x7f00+16 {
		clientFinishedLabel, serverFinishedLabel = "", ""
	}

	serverFinishedKey := hkdfExpandLabel(hash, sHandshakeTS, nil, serverFinishedLabel+"finished", hash.Size())
	clientFinishedKey := hkdfExpandLabel(hash, cHandshakeTS, nil, clientFinishedLabel+"finished", hash.Size())

	h := hmac.New(hash.New, serverFinishedKey)
	h.Write(hs.finishedHash.Sum())
	h.Write(resCtx)
	verifyData := h.Sum(nil)
	serverFinished := &finishedMsg{
		verifyData: verifyData,
	}
	hs.finishedHash.Write(serverFinished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, serverFinished.marshal()); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}
	h = hmac.New(hash.New, clientFinishedKey)
	h.Write(hs.finishedHash.Sum())
	h.Write(resCtx)
	expectedVerifyData := h.Sum(nil)
	if len(expectedVerifyData) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(expectedVerifyData, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	masterSecret := hkdfExtract(hash, nil, handshakeSecret)
	handshakeCtx = hs.finishedHash.Sum()

	cTrafficSecret0 := deriveSecret(hash, masterSecret, handshakeCtx, clientLabel+"application traffic secret")
	cKey = hkdfExpandLabel(hash, cTrafficSecret0, nil, "application data key expansion, "+clientExpandLabel+"key", hs.suite.keyLen)
	cIV = hkdfExpandLabel(hash, cTrafficSecret0, nil, "application data key expansion, "+clientExpandLabel+"iv", 12)
	sTrafficSecret0 := deriveSecret(hash, masterSecret, handshakeCtx, serverLabel+"application traffic secret")
	sKey = hkdfExpandLabel(hash, sTrafficSecret0, nil, "application data key expansion, "+serverExpandLabel+"key", hs.suite.keyLen)
	sIV = hkdfExpandLabel(hash, sTrafficSecret0, nil, "application data key expansion, "+serverExpandLabel+"iv", 12)

	clientCipher = aead(cKey, cIV)
	serverCipher = aead(sKey, sIV)

	c.in.prepareCipherSpec(c.vers, clientCipher, nil)
	c.out.prepareCipherSpec(c.vers, serverCipher, nil)
	c.in.changeCipherSpec()
	c.out.changeCipherSpec()

	return nil
}

func (hs *serverHandshakeState) selectTLS13SignatureScheme() (signatureAndHash, crypto.Hash, error) {
	pk := hs.cert.PrivateKey.(crypto.Signer).Public()
	var pkType string
	if _, ok := pk.(*rsa.PublicKey); ok {
		pkType = "rsa"
	} else if pk, ok := pk.(*ecdsa.PublicKey); ok {
		switch pk.Curve {
		case elliptic.P256():
			pkType = "p256"
		case elliptic.P384():
			pkType = "p384"
		case elliptic.P521():
			pkType = "p521"
		default:
			return signatureAndHash{}, 0, errors.New("tls: unknown ECDSA certificate curve")
		}
	} else {
		return signatureAndHash{}, 0, errors.New("tls: unknown certificate key type")
	}

	for _, sah := range hs.clientHello.signatureAndHashes {
		switch {
		case pkType == "rsa" && sah.hash == 0x08 && sah.signature <= 0x06 && sah.signature >= 0x04: // rsa_pss_*
			fallthrough
		case pkType == "rsa" && sah.hash == 0x07 && sah.signature <= 0x02: // legacy
			switch sah.signature {
			case 0x00, 0x04: // rsa_pss_sha256
				return sah, crypto.SHA256, nil
			case 0x01, 0x05: // rsa_pss_sha384
				return sah, crypto.SHA384, nil
			case 0x02, 0x06: // rsa_pss_sha512
				return sah, crypto.SHA512, nil
			}
		case pkType == "p256" && sah.signature == 0x03 && sah.hash == 0x04: // ecdsa_secp256r1_sha256
			return sah, crypto.SHA256, nil
		case pkType == "p384" && sah.signature == 0x03 && sah.hash == 0x05: // ecdsa_secp384r1_sha384
			return sah, crypto.SHA384, nil
		case pkType == "p521" && sah.signature == 0x03 && sah.hash == 0x06: // ecdsa_secp521r1_sha512
			return sah, crypto.SHA512, nil
		}
	}

	// Fallbacks (https://tlswg.github.io/tls13-spec/#rfc.section.4.3.1.1)
	switch pkType {
	case "rsa":
		return signatureAndHash{hash: 0x08, signature: 0x04}, crypto.SHA256, nil // rsa_pss_sha256
	case "p256":
		return signatureAndHash{hash: 0x04, signature: 0x03}, crypto.SHA256, nil // ecdsa_secp256r1_sha256
	case "p384":
		return signatureAndHash{hash: 0x05, signature: 0x03}, crypto.SHA384, nil // ecdsa_secp384r1_sha384
	case "p521":
		return signatureAndHash{hash: 0x06, signature: 0x03}, crypto.SHA512, nil // ecdsa_secp521r1_sha512
	default:
		panic("unreachable")
	}
}

func prepareDigitallySigned(hash crypto.Hash, context string, data []byte) []byte {
	message := bytes.Repeat([]byte{32}, 64)
	message = append(message, context...)
	message = append(message, 0)
	message = append(message, data...)
	h := hash.New()
	h.Write(message)
	return h.Sum(nil)
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

	return curve, privateKey, &keyShare{group: curveID, data: ecdhePublic}, nil
}

func deriveECDHESecret(curve elliptic.Curve, ks, pk []byte) []byte {
	if len(ks) < 1 {
		return nil
	}
	x, y := elliptic.Unmarshal(curve, ks)
	if x == nil {
		return nil
	}
	x1, _ := curve.ScalarMult(x, y, pk)
	x1Bytes := x1.Bytes()
	curveSize := (curve.Params().BitSize + 8 - 1) / 8
	if len(x1Bytes) != curveSize {
		buf := make([]byte, curveSize)
		copy(buf[curveSize-len(x1Bytes):], x1Bytes)
		x1Bytes = buf
	}
	return x1Bytes
}

func deriveSecret(hash crypto.Hash, secret, messagesHash []byte, label string) []byte {
	resCtx := hash.New()
	resCtx.Write(make([]byte, hash.Size()))
	hashValue := resCtx.Sum(messagesHash)
	return hkdfExpandLabel(hash, secret, hashValue, label, hash.Size())
}

func hkdfExpandLabel(hash crypto.Hash, secret, hashValue []byte, label string, L int) []byte {
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

	return hkdfExpand(hash, secret, hkdfLabel, L)
}

// QuietError is an error wrapper that prevents the verbose handshake log
// dump on errors. Exposed for use by GetCertificate.
type QuietError struct {
	Err error
}

func (e QuietError) Error() string {
	return e.Err.Error()
}

func (hs *serverHandshakeState) traceErr(err error) {
	if err == nil {
		return
	}
	if _, ok := err.(QuietError); ok {
		return
	}
	if os.Getenv("TLSDEBUG") == "error" {
		if hs != nil && hs.clientHello != nil {
			os.Stderr.WriteString(hex.Dump(hs.clientHello.marshal()))
		} else if err == io.EOF {
			return // don't stack trace on EOF before CH
		}
		fmt.Fprintf(os.Stderr, "\n%s\n", debug.Stack())
	}
}
