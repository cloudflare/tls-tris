package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"golang_org/x/crypto/curve25519"
)

// numSessionTickets is the number of different session tickets the
// server sends to a TLS 1.3 client, whom will use each only once.
const numSessionTickets = 2

func (hs *serverHandshakeState) doTLS13Handshake() error {
	config := hs.c.config
	c := hs.c

	hs.c.cipherSuite, hs.hello13.cipherSuite = hs.suite.id, hs.suite.id
	hs.c.clientHello = hs.clientHello.marshal()

	// When picking the group for the handshake, priority is given to groups
	// that the client provided a keyShare for, so to avoid a round-trip.
	// After that the order of CurvePreferences is respected.
	var ks keyShare
CurvePreferenceLoop:
	for _, curveID := range config.curvePreferences() {
		for _, keyShare := range hs.clientHello.keyShares {
			if curveID == keyShare.group {
				ks = keyShare
				break CurvePreferenceLoop
			}
		}
	}
	if ks.group == 0 {
		c.sendAlert(alertInternalError)
		return errors.New("tls: HelloRetryRequest not implemented") // TODO(filippo)
	}

	if committer, ok := c.conn.(Committer); ok {
		if err := committer.Commit(); err != nil {
			return err
		}
	}

	privateKey, serverKS, err := config.generateKeyShare(ks.group)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello13.keyShare = serverKS

	hash := hashForSuite(hs.suite)
	hashSize := hash.Size()

	earlySecret, pskAlert := hs.checkPSK()
	switch {
	case pskAlert != alertSuccess:
		c.sendAlert(pskAlert)
		return errors.New("tls: invalid client PSK")
	case earlySecret == nil:
		earlySecret = hkdfExtract(hash, nil, nil)
	case earlySecret != nil:
		c.didResume = true
	}

	// Negotiate short headers
	if config.AllowShortHeaders && hs.clientHello.shortHeaders {
		hs.hello13.shortHeaders = true
	}

	hs.finishedHash13 = hash.New()
	hs.finishedHash13.Write(hs.clientHello.marshal())

	handshakeCtx := hs.finishedHash13.Sum(nil)
	earlyClientCipher, _ := hs.prepareCipher(handshakeCtx, earlySecret, "client early traffic secret")

	ecdheSecret := deriveECDHESecret(ks, privateKey)
	if ecdheSecret == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: bad ECDHE client share")
	}

	hs.finishedHash13.Write(hs.hello13.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello13.marshal()); err != nil {
		return err
	}

	handshakeSecret := hkdfExtract(hash, ecdheSecret, earlySecret)
	handshakeCtx = hs.finishedHash13.Sum(nil)
	clientCipher, cTrafficSecret := hs.prepareCipher(handshakeCtx, handshakeSecret, "client handshake traffic secret")
	hs.hsClientCipher = clientCipher
	serverCipher, sTrafficSecret := hs.prepareCipher(handshakeCtx, handshakeSecret, "server handshake traffic secret")
	c.out.setCipher(c.vers, serverCipher)

	serverFinishedKey := hkdfExpandLabel(hash, sTrafficSecret, nil, "finished", hashSize)
	hs.clientFinishedKey = hkdfExpandLabel(hash, cTrafficSecret, nil, "finished", hashSize)

	if hs.hello13.shortHeaders {
		c.in.shortHeaders = true
		c.out.shortHeaders = true
	}

	hs.finishedHash13.Write(hs.hello13Enc.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello13Enc.marshal()); err != nil {
		return err
	}

	if !c.didResume {
		if err := hs.sendCertificate13(); err != nil {
			return err
		}
	}

	verifyData := hmacOfSum(hash, hs.finishedHash13, serverFinishedKey)
	serverFinished := &finishedMsg{
		verifyData: verifyData,
	}
	hs.finishedHash13.Write(serverFinished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, serverFinished.marshal()); err != nil {
		return err
	}

	hs.masterSecret = hkdfExtract(hash, nil, handshakeSecret)
	handshakeCtx = hs.finishedHash13.Sum(nil)
	hs.appClientCipher, _ = hs.prepareCipher(handshakeCtx, hs.masterSecret, "client application traffic secret")
	serverCipher, _ = hs.prepareCipher(handshakeCtx, hs.masterSecret, "server application traffic secret")
	c.out.setCipher(c.vers, serverCipher)

	if c.hand.Len() > 0 {
		return c.sendAlert(alertUnexpectedMessage)
	}
	if hs.hello13Enc.earlyData {
		c.in.setCipher(c.vers, earlyClientCipher)
		c.phase = readingEarlyData
	} else if hs.clientHello.earlyData {
		c.in.setCipher(c.vers, hs.hsClientCipher)
		c.phase = discardingEarlyData
	} else {
		c.in.setCipher(c.vers, hs.hsClientCipher)
		c.phase = waitingClientFinished
	}

	return nil
}

// readClientFinished13 is called when, on the second flight of the client,
// a handshake message is received. This might be immediately or after the
// early data. Once done it sends the session tickets. Under c.in lock.
func (hs *serverHandshakeState) readClientFinished13() error {
	c := hs.c

	c.phase = readingClientFinished
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	hash := hashForSuite(hs.suite)
	expectedVerifyData := hmacOfSum(hash, hs.finishedHash13, hs.clientFinishedKey)
	if len(expectedVerifyData) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(expectedVerifyData, clientFinished.verifyData) != 1 {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: client's Finished message is incorrect")
	}
	hs.finishedHash13.Write(clientFinished.marshal())

	c.hs = nil // Discard the server handshake state
	if c.hand.Len() > 0 {
		return c.sendAlert(alertUnexpectedMessage)
	}
	c.in.setCipher(c.vers, hs.appClientCipher)
	c.in.traceErr, c.out.traceErr = nil, nil
	c.phase = handshakeConfirmed
	atomic.StoreInt32(&c.handshakeConfirmed, 1)

	// Any read operation after handshakeRunning and before handshakeConfirmed
	// will be holding this lock, which we release as soon as the confirmation
	// happens, even if the Read call might do more work.
	c.confirmMutex.Unlock()

	return hs.sendSessionTicket13() // TODO: do in a goroutine
}

func (hs *serverHandshakeState) sendCertificate13() error {
	c := hs.c

	certEntries := []certificateEntry{}
	for _, cert := range hs.cert.Certificate {
		certEntries = append(certEntries, certificateEntry{data: cert})
	}
	if len(certEntries) > 0 && hs.clientHello.ocspStapling {
		certEntries[0].ocspStaple = hs.cert.OCSPStaple
	}
	if len(certEntries) > 0 && hs.clientHello.scts {
		certEntries[0].sctList = hs.cert.SignedCertificateTimestamps
	}
	certMsg := &certificateMsg13{certificates: certEntries}

	hs.finishedHash13.Write(certMsg.marshal())
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

	toSign := prepareDigitallySigned(sigHash, "TLS 1.3, server CertificateVerify", hs.finishedHash13.Sum(nil))
	signature, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), toSign[:], opts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	verifyMsg := &certificateVerifyMsg{
		hasSignatureAndHash: true,
		signatureAndHash:    sigSchemeToSigAndHash(sigScheme),
		signature:           signature,
	}
	hs.finishedHash13.Write(verifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, verifyMsg.marshal()); err != nil {
		return err
	}

	return nil
}

func (c *Conn) handleEndOfEarlyData() {
	if c.phase != readingEarlyData || c.vers < VersionTLS13 {
		c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		return
	}
	c.phase = waitingClientFinished
	if c.hand.Len() > 0 {
		c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		return
	}
	c.in.setCipher(c.vers, c.hs.hsClientCipher)
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

func hashForSuite(suite *cipherSuite) crypto.Hash {
	if suite.flags&suiteSHA384 != 0 {
		return crypto.SHA384
	}
	return crypto.SHA256
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

func hmacOfSum(f crypto.Hash, hash hash.Hash, key []byte) []byte {
	h := hmac.New(f.New, key)
	h.Write(hash.Sum(nil))
	return h.Sum(nil)
}

func (hs *serverHandshakeState) prepareCipher(handshakeCtx, secret []byte, label string) (interface{}, []byte) {
	hash := hashForSuite(hs.suite)
	trafficSecret := hkdfExpandLabel(hash, secret, handshakeCtx, label, hash.Size())
	key := hkdfExpandLabel(hash, trafficSecret, nil, "key", hs.suite.keyLen)
	iv := hkdfExpandLabel(hash, trafficSecret, nil, "iv", 12)
	return hs.suite.aead(key, iv), trafficSecret
}

// Maximum allowed mismatch between the stated age of a ticket
// and the server-observed one. See
// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.8.2.
const ticketAgeSkewAllowance = 10 * time.Second

func (hs *serverHandshakeState) checkPSK() (earlySecret []byte, alert alert) {
	if hs.c.config.SessionTicketsDisabled {
		return nil, alertSuccess
	}

	foundDHE := false
	for _, mode := range hs.clientHello.pskKeyExchangeModes {
		if mode == pskDHEKeyExchange {
			foundDHE = true
			break
		}
	}
	if !foundDHE {
		return nil, alertSuccess
	}

	hash := hashForSuite(hs.suite)
	hashSize := hash.Size()
	for i := range hs.clientHello.psks {
		sessionTicket := append([]uint8{}, hs.clientHello.psks[i].identity...)
		if hs.c.config.SessionTicketSealer != nil {
			var ok bool
			sessionTicket, ok = hs.c.config.SessionTicketSealer.Unseal(hs.clientHelloInfo(), sessionTicket)
			if !ok {
				continue
			}
		} else {
			sessionTicket, _ = hs.c.decryptTicket(sessionTicket)
			if sessionTicket == nil {
				continue
			}
		}
		s := &sessionState13{}
		if s.unmarshal(sessionTicket) != alertSuccess {
			continue
		}
		if s.vers != hs.c.vers {
			continue
		}
		clientAge := time.Duration(hs.clientHello.psks[i].obfTicketAge-s.ageAdd) * time.Millisecond
		serverAge := time.Since(time.Unix(int64(s.createdAt), 0))
		if clientAge-serverAge > ticketAgeSkewAllowance || clientAge-serverAge < -ticketAgeSkewAllowance {
			// XXX: NSS is off spec and sends obfuscated_ticket_age as seconds
			clientAge = time.Duration(hs.clientHello.psks[i].obfTicketAge-s.ageAdd) * time.Second
			if clientAge-serverAge > ticketAgeSkewAllowance || clientAge-serverAge < -ticketAgeSkewAllowance {
				continue
			}
		}

		// This enforces the stricter 0-RTT requirements on all ticket uses.
		// The benefit of using PSK+ECDHE without 0-RTT are small enough that
		// we can give them up in the edge case of changed suite or ALPN or SNI.
		if s.suite != hs.suite.id {
			continue
		}
		if s.alpnProtocol != hs.c.clientProtocol {
			continue
		}
		if s.SNI != hs.c.serverName {
			continue
		}

		earlySecret := hkdfExtract(hash, s.resumptionSecret, nil)
		handshakeCtx := hash.New().Sum(nil)
		binderKey := hkdfExpandLabel(hash, earlySecret, handshakeCtx, "resumption psk binder key", hashSize)
		binderFinishedKey := hkdfExpandLabel(hash, binderKey, nil, "finished", hashSize)
		chHash := hash.New()
		chHash.Write(hs.clientHello.rawTruncated)
		expectedBinder := hmacOfSum(hash, chHash, binderFinishedKey)

		if subtle.ConstantTimeCompare(expectedBinder, hs.clientHello.psks[i].binder) != 1 {
			return nil, alertDecryptError
		}

		if i == 0 && hs.clientHello.earlyData {
			// This is a ticket intended to be used for 0-RTT
			if s.maxEarlyDataLen == 0 {
				// But we had not tagged it as such.
				return nil, alertIllegalParameter
			}
			if hs.c.config.Accept0RTTData {
				hs.c.binder = expectedBinder
				hs.c.ticketMaxEarlyData = int64(s.maxEarlyDataLen)
				hs.hello13Enc.earlyData = true
			}
		}
		hs.hello13.psk = true
		hs.hello13.pskIdentity = uint16(i)
		return earlySecret, alertSuccess
	}

	return nil, alertSuccess
}

func (hs *serverHandshakeState) sendSessionTicket13() error {
	c := hs.c
	if c.config.SessionTicketsDisabled {
		return nil
	}

	foundDHE := false
	for _, mode := range hs.clientHello.pskKeyExchangeModes {
		if mode == pskDHEKeyExchange {
			foundDHE = true
			break
		}
	}
	if !foundDHE {
		return nil
	}

	hash := hashForSuite(hs.suite)
	handshakeCtx := hs.finishedHash13.Sum(nil)
	resumptionSecret := hkdfExpandLabel(hash, hs.masterSecret, handshakeCtx, "resumption master secret", hash.Size())

	ageAddBuf := make([]byte, 4)
	sessionState := &sessionState13{
		vers:             c.vers,
		suite:            hs.suite.id,
		createdAt:        uint64(time.Now().Unix()),
		resumptionSecret: resumptionSecret,
		alpnProtocol:     c.clientProtocol,
		SNI:              c.serverName,
		maxEarlyDataLen:  c.config.Max0RTTDataSize,
	}

	for i := 0; i < numSessionTickets; i++ {
		if _, err := io.ReadFull(c.config.rand(), ageAddBuf); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		sessionState.ageAdd = uint32(ageAddBuf[0])<<24 | uint32(ageAddBuf[1])<<16 |
			uint32(ageAddBuf[2])<<8 | uint32(ageAddBuf[3])
		ticket := sessionState.marshal()
		var err error
		if c.config.SessionTicketSealer != nil {
			cs := c.ConnectionState()
			ticket, err = c.config.SessionTicketSealer.Seal(&cs, ticket)
		} else {
			ticket, err = c.encryptTicket(ticket)
		}
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		if ticket == nil {
			continue
		}
		ticketMsg := &newSessionTicketMsg13{
			lifetime:           24 * 3600, // TODO(filippo)
			maxEarlyDataLength: c.config.Max0RTTDataSize,
			withEarlyDataInfo:  c.config.Max0RTTDataSize > 0,
			ageAdd:             sessionState.ageAdd,
			ticket:             ticket,
		}
		if _, err := c.writeRecord(recordTypeHandshake, ticketMsg.marshal()); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeState) traceErr(err error) {
	if err == nil {
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
	if os.Getenv("TLSDEBUG") == "short" {
		var pcs [4]uintptr
		frames := runtime.CallersFrames(pcs[0:runtime.Callers(3, pcs[:])])
		for {
			frame, more := frames.Next()
			if frame.Function != "crypto/tls.(*halfConn).setErrorLocked" &&
				frame.Function != "crypto/tls.(*Conn).sendAlertLocked" &&
				frame.Function != "crypto/tls.(*Conn).sendAlert" {
				file := frame.File[strings.LastIndex(frame.File, "/")+1:]
				log.Printf("%s:%d (%s): %v", file, frame.Line, frame.Function, err)
				return
			}
			if !more {
				break
			}
		}
	}
}
