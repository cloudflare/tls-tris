package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"io"

	"golang_org/x/crypto/curve25519"
)

func (hs *serverHandshakeState) doTLS13Handshake() error {
	config := hs.c.config
	c := hs.c

	hs.c.cipherSuite, hs.hello13.cipherSuite = hs.suite.id, hs.suite.id
	hs.c.clientHello = hs.clientHello.marshal()

	// When picking the group for the handshake, priority is given to groups
	// that the client provided a keyShare for, so to avoid a round-trip.
	// After that the order of CurvePreferences is respected.
	var ks keyShare
	for _, curveID := range config.curvePreferences() {
		for _, keyShare := range hs.clientHello.keyShares {
			if curveID == keyShare.group {
				ks = keyShare
				break
			}
		}
	}
	if ks.group == 0 {
		c.sendAlert(alertInternalError)
		return errors.New("tls: HelloRetryRequest not implemented") // TODO(filippo)
	}

	privateKey, serverKS, err := config.generateKeyShare(ks.group)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello13.keyShare = serverKS

	hash := crypto.SHA256
	if hs.suite.flags&suiteSHA384 != 0 {
		hash = crypto.SHA384
	}
	hashSize := hash.Size()

	ecdheSecret := deriveECDHESecret(ks, privateKey)
	if ecdheSecret == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello13.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello13.marshal()); err != nil {
		return err
	}

	earlySecret := hkdfExtract(hash, nil, nil)
	handshakeSecret := hkdfExtract(hash, ecdheSecret, earlySecret)

	handshakeCtx := hs.finishedHash.Sum()

	cHandshakeTS := hkdfExpandLabel(hash, handshakeSecret, handshakeCtx, "client handshake traffic secret", hashSize)
	cKey := hkdfExpandLabel(hash, cHandshakeTS, nil, "key", hs.suite.keyLen)
	cIV := hkdfExpandLabel(hash, cHandshakeTS, nil, "iv", 12)
	sHandshakeTS := hkdfExpandLabel(hash, handshakeSecret, handshakeCtx, "server handshake traffic secret", hashSize)
	sKey := hkdfExpandLabel(hash, sHandshakeTS, nil, "key", hs.suite.keyLen)
	sIV := hkdfExpandLabel(hash, sHandshakeTS, nil, "iv", 12)

	clientCipher := hs.suite.aead(cKey, cIV)
	c.in.setCipher(c.vers, clientCipher)
	serverCipher := hs.suite.aead(sKey, sIV)
	c.out.setCipher(c.vers, serverCipher)

	hs.finishedHash.Write(hs.hello13Enc.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello13Enc.marshal()); err != nil {
		return err
	}

	certMsg := &certificateMsg13{
		certificates: hs.cert.Certificate,
	}
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	sigScheme, err := hs.selectTLS13SignatureScheme()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	sigHash := hashForSignatureScheme(sigScheme)
	opts := crypto.SignerOpts(sigHash)
	if signatureSchemeIsPSS(sigScheme) {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}

	toSign := prepareDigitallySigned(sigHash, "TLS 1.3, server CertificateVerify", hs.finishedHash.Sum())
	signature, err := hs.cert.PrivateKey.(crypto.Signer).Sign(config.rand(), toSign[:], opts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	verifyMsg := &certificateVerifyMsg{
		hasSignatureAndHash: true,
		signatureAndHash:    sigSchemeToSigAndHash(sigScheme),
		signature:           signature,
	}
	hs.finishedHash.Write(verifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, verifyMsg.marshal()); err != nil {
		return err
	}

	serverFinishedKey := hkdfExpandLabel(hash, sHandshakeTS, nil, "finished", hashSize)
	clientFinishedKey := hkdfExpandLabel(hash, cHandshakeTS, nil, "finished", hashSize)

	h := hmac.New(hash.New, serverFinishedKey)
	h.Write(hs.finishedHash.Sum())
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
	expectedVerifyData := h.Sum(nil)
	if len(expectedVerifyData) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(expectedVerifyData, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	masterSecret := hkdfExtract(hash, nil, handshakeSecret)
	handshakeCtx = hs.finishedHash.Sum()

	cTrafficSecret0 := hkdfExpandLabel(hash, masterSecret, handshakeCtx, "client application traffic secret", hashSize)
	cKey = hkdfExpandLabel(hash, cTrafficSecret0, nil, "key", hs.suite.keyLen)
	cIV = hkdfExpandLabel(hash, cTrafficSecret0, nil, "iv", 12)
	sTrafficSecret0 := hkdfExpandLabel(hash, masterSecret, handshakeCtx, "server application traffic secret", hashSize)
	sKey = hkdfExpandLabel(hash, sTrafficSecret0, nil, "key", hs.suite.keyLen)
	sIV = hkdfExpandLabel(hash, sTrafficSecret0, nil, "iv", 12)

	clientCipher = hs.suite.aead(cKey, cIV)
	c.in.setCipher(c.vers, clientCipher)
	serverCipher = hs.suite.aead(sKey, sIV)
	c.out.setCipher(c.vers, serverCipher)

	return nil
}

// selectTLS13SignatureScheme chooses the SignatureScheme for the CertificateVerify
// based on the certificate type and client supported schemes. If not overlap is found,
// a fallback is selected.
//
// See https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.4.1.2
func (hs *serverHandshakeState) selectTLS13SignatureScheme() (sigScheme SignatureScheme, err error) {
	var supportedSchemes []SignatureScheme
	signer, ok := hs.cert.PrivateKey.(crypto.Signer)
	if !ok {
		return 0, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	pk := signer.Public()
	if _, ok := pk.(*rsa.PublicKey); ok {
		sigScheme = PSSWithSHA256
		supportedSchemes = []SignatureScheme{PSSWithSHA256, PSSWithSHA384, PSSWithSHA512}
	} else if pk, ok := pk.(*ecdsa.PublicKey); ok {
		switch pk.Curve {
		case elliptic.P256():
			sigScheme = ECDSAWithP256AndSHA256
			supportedSchemes = []SignatureScheme{ECDSAWithP256AndSHA256}
		case elliptic.P384():
			sigScheme = ECDSAWithP384AndSHA384
			supportedSchemes = []SignatureScheme{ECDSAWithP384AndSHA384}
		case elliptic.P521():
			sigScheme = ECDSAWithP521AndSHA512
			supportedSchemes = []SignatureScheme{ECDSAWithP521AndSHA512}
		default:
			return 0, errors.New("tls: unknown ECDSA certificate curve")
		}
	} else {
		return 0, errors.New("tls: unknown certificate key type")
	}

	for _, ss := range supportedSchemes {
		for _, cs := range hs.clientHello.signatureAndHashes {
			if ss == sigAndHashToSigScheme(cs) {
				return ss, nil
			}
		}
	}

	return sigScheme, nil
}

func sigSchemeToSigAndHash(s SignatureScheme) (sah signatureAndHash) {
	sah.hash = byte(s >> 8)
	sah.signature = byte(s)
	return
}

func sigAndHashToSigScheme(sah signatureAndHash) SignatureScheme {
	return SignatureScheme(sah.hash)<<8 | SignatureScheme(sah.signature)
}

func signatureSchemeIsPSS(s SignatureScheme) bool {
	return s == PSSWithSHA256 || s == PSSWithSHA384 || s == PSSWithSHA512
}

// hashForSignatureScheme returns the Hash used by a SignatureScheme which is
// supported by selectTLS13SignatureScheme.
func hashForSignatureScheme(ss SignatureScheme) crypto.Hash {
	switch ss {
	case PSSWithSHA256, ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case PSSWithSHA384, ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case PSSWithSHA512, ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		panic("unsupported SignatureScheme passed to hashForSignatureScheme")
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

func (c *Config) generateKeyShare(curveID CurveID) ([]byte, keyShare, error) {
	if curveID == X25519 {
		var scalar, public [32]byte
		if _, err := io.ReadFull(c.rand(), scalar[:]); err != nil {
			return nil, keyShare{}, err
		}

		curve25519.ScalarBaseMult(&public, &scalar)
		return scalar[:], keyShare{group: curveID, data: public[:]}, nil
	}

	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, keyShare{}, errors.New("tls: preferredCurves includes unsupported curve")
	}

	privateKey, x, y, err := elliptic.GenerateKey(curve, c.rand())
	if err != nil {
		return nil, keyShare{}, err
	}
	ecdhePublic := elliptic.Marshal(curve, x, y)

	return privateKey, keyShare{group: curveID, data: ecdhePublic}, nil
}

func deriveECDHESecret(ks keyShare, pk []byte) []byte {
	if ks.group == X25519 {
		if len(ks.data) != 32 {
			return nil
		}

		var theirPublic, sharedKey, scalar [32]byte
		copy(theirPublic[:], ks.data)
		copy(scalar[:], pk)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		return sharedKey[:]
	}

	curve, ok := curveForCurveID(ks.group)
	if !ok {
		return nil
	}
	x, y := elliptic.Unmarshal(curve, ks.data)
	if x == nil {
		return nil
	}
	x, _ = curve.ScalarMult(x, y, pk)
	xBytes := x.Bytes()
	curveSize := (curve.Params().BitSize + 8 - 1) >> 3
	if len(xBytes) == curveSize {
		return xBytes
	}
	buf := make([]byte, curveSize)
	copy(buf[len(buf)-len(xBytes):], xBytes)
	return buf
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
