package tls

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
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
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: received key share for unsupported curve")
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

	ES := deriveECDHESecret(curve, ks.data, privateKey)
	if ES == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}
	dumpKeys("ES:", ES)

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

	xES := hkdfExtract(sha256.New, ES, nil) // TODO(filippo)
	dumpKeys("xES:", xES)
	handshakeCtxt := hs.finishedHash.Sum()
	dumpKeys("Hash:", handshakeCtxt)
	cKey := hkdfExpandLabel(sha256.New, xES, handshakeCtxt, "handshake key expansion, client write key", 16)
	dumpKeys("Client Write Key:", cKey)
	cIV := hkdfExpandLabel(sha256.New, xES, handshakeCtxt, "handshake key expansion, client write iv", 12) // Lowercase because NSS
	dumpKeys("Client Write IV:", cIV)
	sKey := hkdfExpandLabel(sha256.New, xES, handshakeCtxt, "handshake key expansion, server write key", 16)
	dumpKeys("Server Write Key:", sKey)
	sIV := hkdfExpandLabel(sha256.New, xES, handshakeCtxt, "handshake key expansion, server write iv", 12) // Lowercase because NSS
	dumpKeys("Server Write IV:", sIV)

	clientCipher := aeadTLS13(cKey, cIV)
	serverCipher := aeadTLS13(sKey, sIV)

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
	// TODO(filippo): check what the client supports, add support for SHA384
	var opts crypto.SignerOpts = crypto.SHA256
	sigType := signatureAndHash{hash: 0x04, signature: 0x03} // ecdsa_secp256r1_sha256
	if hs.suite.flags&suiteECDSA == 0 {
		// This is what we are supposed to use, but NSS if off-spec and mint goes with it.
		//opts = &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}
		//sigType = signatureAndHash{hash: 0x07, signature: 0x00} // rsa_pss_sha256
		sigType = signatureAndHash{hash: 0x04, signature: 0x01} // rsa_pkcs1_sha256
	}

	toSign := prepareDigitallySigned(sha256.New, "TLS 1.3, server CertificateVerify", hs.finishedHash.Sum())
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

	mSS := hkdfExpandLabel(sha256.New, xES, hs.finishedHash.Sum(), "expanded static secret", sha256.Size)
	dumpKeys("mSS:", mSS)
	mES := hkdfExpandLabel(sha256.New, xES, hs.finishedHash.Sum(), "expanded ephemeral secret", sha256.Size)
	dumpKeys("mES:", mES)
	masterSecret := hkdfExtract(sha256.New, mES, mSS)
	serverFinishedKey := hkdfExpandLabel(sha256.New, masterSecret, nil, "server finished", sha256.Size)
	dumpKeys("Server Finished Key:", serverFinishedKey)
	clientFinishedKey := hkdfExpandLabel(sha256.New, masterSecret, nil, "client finished", sha256.Size)
	dumpKeys("Client Finished Key:", clientFinishedKey)
	trafficSecret0 := hkdfExpandLabel(sha256.New, masterSecret, hs.finishedHash.Sum(), "traffic secret", sha256.Size)
	dumpKeys("Traffic Secret:", trafficSecret0)

	h := hmac.New(sha256.New, serverFinishedKey)
	h.Write(hs.finishedHash.Sum())
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
	h = hmac.New(sha256.New, clientFinishedKey)
	h.Write(hs.finishedHash.Sum())
	expectedVerifyData := h.Sum(nil)
	hs.dump("Client Finished expected:", expectedVerifyData)
	if len(expectedVerifyData) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(expectedVerifyData, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	handshakeCtxt = hs.finishedHash.Sum()
	cKey = hkdfExpandLabel(sha256.New, trafficSecret0, handshakeCtxt, "application data key expansion, client write key", 16)
	dumpKeys("Client Write Key:", cKey)
	cIV = hkdfExpandLabel(sha256.New, trafficSecret0, handshakeCtxt, "application data key expansion, client write iv", 12) // Lowercase because NSS
	dumpKeys("Client Write IV:", cIV)
	sKey = hkdfExpandLabel(sha256.New, trafficSecret0, handshakeCtxt, "application data key expansion, server write key", 16)
	dumpKeys("Server Write Key:", sKey)
	sIV = hkdfExpandLabel(sha256.New, trafficSecret0, handshakeCtxt, "application data key expansion, server write iv", 12) // Lowercase because NSS
	dumpKeys("Server Write IV:", sIV)

	clientCipher = aeadTLS13(cKey, cIV)
	serverCipher = aeadTLS13(sKey, sIV)

	c.in.prepareCipherSpec(c.vers, clientCipher, nil)
	c.out.prepareCipherSpec(c.vers, serverCipher, nil)
	c.in.changeCipherSpec()
	c.out.changeCipherSpec()

	return nil
}

func prepareDigitallySigned(hash func() hash.Hash, context string, data []byte) []byte {
	message := bytes.Repeat([]byte{32}, 64)
	message = append(message, context...)
	message = append(message, 0)
	message = append(message, data...)
	dumpKeys("Padded message to sign:", message)
	h := hash()
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

func hkdfExpandLabel(hash func() hash.Hash, prk, hashValue []byte, label string, L int) []byte {
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

	return hkdfExpand(hash, prk, hkdfLabel, L)
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
