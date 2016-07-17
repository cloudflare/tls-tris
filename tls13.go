package tls

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
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

	hs.dump("ClientHello:", hs.clientHello.marshal())

	// Group choice logic
	//
	// When picking the group for the handshake, priority is given to groups
	// that the client provided a keyShare for, so to avoid a round-trip.
	// After that the order of CurvePreferences is respected.
	//
	// Conveniently, this logic never affects the cipher suite choice, as
	// crypto/tls only supports ECDHE.

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
			// FIXME: NSS is off-spec, so warn instead of failing
			// https://bugzilla.mozilla.org/show_bug.cgi?id=1283646
			//c.sendAlert(alertIllegalParameter)
			//return errors.New("tls: received key share for unsupported curve")
		}
	}

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

	var hash crypto.Hash
	if hs.suite.flags&suiteSHA384 != 0 {
		hash = crypto.SHA384
	} else {
		hash = crypto.SHA256 // TODO(filippo)
	}

	hs.tracef("SignatureScheme: %d CipherSuite: %d", ks.group, c.cipherSuite)

	resCtxHash := hash.New()
	resCtxHash.Write(make([]byte, hash.Size()))
	resCtx := resCtxHash.Sum(nil)

	ecdheSecret := deriveECDHESecret(curve, ks.data, privateKey)
	if ecdheSecret == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}
	dumpKeys("ecdheSecret:", ecdheSecret)

	hs.c.cipherSuite, hs.hello.cipherSuite = hs.suite.id, hs.suite.id
	hs.c.clientHello = hs.clientHello.marshal()

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	hs.dump("ServerHello:", hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	earlySecret := hkdfExtract(hash, nil, nil)
	dumpKeys("Early Secret:", earlySecret)
	handshakeSecret := hkdfExtract(hash, ecdheSecret, earlySecret)
	dumpKeys("Handshake Secret:", handshakeSecret)

	handshakeCtx := hs.finishedHash.Sum()
	dumpKeys("Messages Hash:", handshakeCtx)

	handshakeTrafficSecret := deriveSecret(hash, handshakeSecret, handshakeCtx, "handshake traffic secret")
	dumpKeys("Handshake Traffic Secret:", handshakeTrafficSecret)

	cKey := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "handshake key expansion, client write key", hs.suite.keyLen)
	dumpKeys("Client Write Key:", cKey)
	cIV := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "handshake key expansion, client write iv", hs.suite.ivLen)
	dumpKeys("Client Write IV:", cIV)
	sKey := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "handshake key expansion, server write key", hs.suite.keyLen)
	dumpKeys("Server Write Key:", sKey)
	sIV := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "handshake key expansion, server write iv", hs.suite.ivLen)
	dumpKeys("Server Write IV:", sIV)

	clientCipher := hs.suite.aead(cKey, cIV)
	serverCipher := hs.suite.aead(sKey, sIV)

	c.in.prepareCipherSpec(c.vers, clientCipher, nil)
	c.out.prepareCipherSpec(c.vers, serverCipher, nil)
	c.in.changeCipherSpec()
	c.out.changeCipherSpec()

	hs.finishedHash.Write(hs.hello.marshalEncExtensions())
	hs.dump("EncryptedExtensions:", hs.hello.marshalEncExtensions())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshalEncExtensions()); err != nil {
		return err
	}

	certMsg := &certificateMsg{
		requestContext: true,
		certificates:   hs.cert.Certificate,
	}
	hs.finishedHash.Write(certMsg.marshal())
	hs.dump("Certificate:", certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	// TODO(filippo): need a new, proper type for 1.3 SignatureScheme
	var sigHash crypto.Hash
	var hashType uint8
	if hs.suite.flags&suiteSHA384 != 0 {
		sigHash = crypto.SHA384
		hashType = 0x05
	} else {
		sigHash = crypto.SHA256 // TODO(filippo)
		hashType = 0x04
	}
	opts := crypto.SignerOpts(sigHash)
	sigType := signatureAndHash{hash: hashType, signature: 0x03} // ecdsa_secp256r1_sha256
	if hs.suite.flags&suiteECDSA == 0 {
		// This is what we are supposed to use, but NSS if off-spec and mint goes with it.
		//opts = &rsa.PSSOptions{SaltLength: sigHash.Size(), Hash: sigHash}
		//sigType = signatureAndHash{hash: 0x07, signature: 0x00} // rsa_pss_sha256
		sigType = signatureAndHash{hash: hashType, signature: 0x01} // rsa_pkcs1_sha256
	}

	hashedData := append(hs.finishedHash.Sum(), resCtx...)
	toSign := prepareDigitallySigned(sigHash, "TLS 1.3, server CertificateVerify", hashedData)
	signature, err := hs.cert.PrivateKey.(crypto.Signer).Sign(config.rand(), toSign[:], opts)
	if err != nil {
		return err
	}

	verifyMsg := &certificateVerifyMsg{
		hasSignatureAndHash: true,
		signatureAndHash:    sigType,
		signature:           signature,
	}
	hs.finishedHash.Write(verifyMsg.marshal())
	hs.dump("CertificateVerify", verifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, verifyMsg.marshal()); err != nil {
		return err
	}

	serverFinishedKey := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "server finished", hash.Size())
	dumpKeys("Server Finished Key:", serverFinishedKey)
	clientFinishedKey := hkdfExpandLabel(hash, handshakeTrafficSecret, nil, "client finished", hash.Size())
	dumpKeys("Client Finished Key:", clientFinishedKey)

	h := hmac.New(hash.New, serverFinishedKey)
	h.Write(hs.finishedHash.Sum())
	h.Write(resCtx)
	verifyData := h.Sum(nil)
	serverFinished := &finishedMsg{
		verifyData: verifyData,
	}
	hs.finishedHash.Write(serverFinished.marshal())
	hs.dump("Finished:", serverFinished.marshal())
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
	hs.dump("Client Finished received:", clientFinished.verifyData)
	h = hmac.New(hash.New, clientFinishedKey)
	h.Write(hs.finishedHash.Sum())
	h.Write(resCtx)
	expectedVerifyData := h.Sum(nil)
	hs.dump("Client Finished expected:", expectedVerifyData)
	if len(expectedVerifyData) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(expectedVerifyData, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	masterSecret := hkdfExtract(hash, nil, handshakeSecret)
	dumpKeys("Master Secret:", masterSecret)
	handshakeCtx = hs.finishedHash.Sum()
	trafficSecret0 := deriveSecret(hash, masterSecret, handshakeCtx, "application traffic secret")
	dumpKeys("Traffic Secret 0:", trafficSecret0)

	cKey = hkdfExpandLabel(hash, trafficSecret0, nil, "application data key expansion, client write key", hs.suite.keyLen)
	dumpKeys("Client Write Key:", cKey)
	cIV = hkdfExpandLabel(hash, trafficSecret0, nil, "application data key expansion, client write iv", hs.suite.ivLen)
	dumpKeys("Client Write IV:", cIV)
	sKey = hkdfExpandLabel(hash, trafficSecret0, nil, "application data key expansion, server write key", hs.suite.keyLen)
	dumpKeys("Server Write Key:", sKey)
	sIV = hkdfExpandLabel(hash, trafficSecret0, nil, "application data key expansion, server write iv", hs.suite.ivLen)
	dumpKeys("Server Write IV:", sIV)

	clientCipher = hs.suite.aead(cKey, cIV)
	serverCipher = hs.suite.aead(sKey, sIV)

	c.in.prepareCipherSpec(c.vers, clientCipher, nil)
	c.out.prepareCipherSpec(c.vers, serverCipher, nil)
	c.in.changeCipherSpec()
	c.out.changeCipherSpec()

	return nil
}

func prepareDigitallySigned(hash crypto.Hash, context string, data []byte) []byte {
	message := bytes.Repeat([]byte{32}, 64)
	message = append(message, context...)
	message = append(message, 0)
	message = append(message, data...)
	dumpKeys("Padded message to sign:", message)
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
	curveSize := curve.Params().P.BitLen() / 8
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

	dumpKeys("Label:", hkdfLabel)

	return hkdfExpand(hash, secret, hkdfLabel, L)
}

func (hs *serverHandshakeState) tracef(format string, a ...interface{}) {
	var output io.Writer
	switch os.Getenv("TLSDEBUG") {
	case "error":
		output = &hs.trace
	case "live", "keys":
		output = os.Stderr
	default:
		return
	}
	fmt.Fprintf(output, format, a...)
}

func (hs *serverHandshakeState) dump(label string, data []byte) {
	hs.tracef("%s\n%s\n", label, hex.Dump(data))
}

func (hs *serverHandshakeState) traceErr(err error) {
	if err == nil {
		return
	}
	hs.tracef("%s\n%v\n", debug.Stack(), err)
	if os.Getenv("TLSDEBUG") == "error" {
		io.Copy(os.Stderr, &hs.trace)
	}
}

func dumpKeys(label string, data []byte) {
	if os.Getenv("TLSDEBUG") == "keys" {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", label, hex.Dump(data))
	}
}
