// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "bytes"

type clientHelloMsg struct {
	raw                          []byte
	rawTruncated                 []byte // for PSK binding
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	nextProtoNeg                 bool
	serverName                   string
	ocspStapling                 bool
	scts                         bool
	supportedCurves              []CurveID
	supportedPoints              []uint8
	ticketSupported              bool
	sessionTicket                []uint8
	signatureAndHashes           []signatureAndHash
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocols                []string
	keyShares                    []keyShare
	supportedVersions            []uint16
	psks                         []psk
	pskKeyExchangeModes          []uint8
	earlyData                    bool
	shortHeaders                 bool
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		m.serverName == m1.serverName &&
		m.ocspStapling == m1.ocspStapling &&
		m.scts == m1.scts &&
		eqCurveIDs(m.supportedCurves, m1.supportedCurves) &&
		bytes.Equal(m.supportedPoints, m1.supportedPoints) &&
		m.ticketSupported == m1.ticketSupported &&
		bytes.Equal(m.sessionTicket, m1.sessionTicket) &&
		eqSignatureAndHashes(m.signatureAndHashes, m1.signatureAndHashes) &&
		m.secureRenegotiationSupported == m1.secureRenegotiationSupported &&
		bytes.Equal(m.secureRenegotiation, m1.secureRenegotiation) &&
		eqStrings(m.alpnProtocols, m1.alpnProtocols) &&
		eqKeyShares(m.keyShares, m1.keyShares) &&
		eqUint16s(m.supportedVersions, m1.supportedVersions) &&
		m.earlyData == m1.earlyData &&
		m.shortHeaders == m1.shortHeaders
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.nextProtoNeg {
		numExtensions++
	}
	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if len(m.supportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.supportedCurves)
		numExtensions++
	}
	if len(m.supportedPoints) > 0 {
		extensionsLength += 1 + len(m.supportedPoints)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
	if len(m.signatureAndHashes) > 0 {
		extensionsLength += 2 + 2*len(m.signatureAndHashes)
		numExtensions++
	}
	if m.secureRenegotiationSupported {
		extensionsLength += 1 + len(m.secureRenegotiation)
		numExtensions++
	}
	if len(m.alpnProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.alpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if m.scts {
		numExtensions++
	}
	if len(m.keyShares) > 0 {
		extensionsLength += 2
		for _, k := range m.keyShares {
			extensionsLength += 4 + len(k.data)
		}
		numExtensions++
	}
	if len(m.supportedVersions) > 0 {
		extensionsLength += 1 + 2*len(m.supportedVersions)
		numExtensions++
	}
	if m.earlyData {
		numExtensions++
	}
	if m.shortHeaders {
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.4
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.supportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.supportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.supportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.supportedPoints {
			z[0] = pointFormat
			z = z[1:]
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}
	if len(m.signatureAndHashes) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3
		z[0] = byte(extensionSignatureAlgorithms >> 8)
		z[1] = byte(extensionSignatureAlgorithms)
		l := 2 + 2*len(m.signatureAndHashes)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, sigAndHash := range m.signatureAndHashes {
			z[0] = sigAndHash.hash
			z[1] = sigAndHash.signature
			z = z[2:]
		}
	}
	if m.secureRenegotiationSupported {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = byte(len(m.secureRenegotiation) + 1)
		z[4] = byte(len(m.secureRenegotiation))
		z = z[5:]
		copy(z, m.secureRenegotiation)
		z = z[len(m.secureRenegotiation):]
	}
	if len(m.alpnProtocols) > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.alpnProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}
	if m.scts {
		// https://tools.ietf.org/html/rfc6962#section-3.3.1
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		// zero uint16 for the zero-length extension_data
		z = z[4:]
	}
	if len(m.keyShares) > 0 {
		// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.5
		z[0] = byte(extensionKeyShare >> 8)
		z[1] = byte(extensionKeyShare)
		lengths := z[2:]
		z = z[6:]

		totalLength := 0
		for _, ks := range m.keyShares {
			z[0] = byte(ks.group >> 8)
			z[1] = byte(ks.group)
			z[2] = byte(len(ks.data) >> 8)
			z[3] = byte(len(ks.data))
			copy(z[4:], ks.data)
			z = z[4+len(ks.data):]
			totalLength += 4 + len(ks.data)
		}

		lengths[2] = byte(totalLength >> 8)
		lengths[3] = byte(totalLength)
		totalLength += 2
		lengths[0] = byte(totalLength >> 8)
		lengths[1] = byte(totalLength)
	}
	if len(m.supportedVersions) > 0 {
		z[0] = byte(extensionSupportedVersions >> 8)
		z[1] = byte(extensionSupportedVersions)
		l := 1 + 2*len(m.supportedVersions)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 1
		z[4] = byte(l)
		z = z[5:]
		for _, v := range m.supportedVersions {
			z[0] = byte(v >> 8)
			z[1] = byte(v)
			z = z[2:]
		}
	}
	if m.earlyData {
		z[0] = byte(extensionEarlyData >> 8)
		z[1] = byte(extensionEarlyData)
		z = z[4:]
	}
	if m.shortHeaders {
		z[0] = byte(extensionShortHeaders >> 8)
		z[1] = byte(extensionShortHeaders & 0xff)
		z = z[4:]
	}

	m.raw = x

	return x
}

func (m *clientHelloMsg) unmarshal(data []byte) alert {
	if len(data) < 42 {
		return alertDecodeError
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return alertDecodeError
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	bindersOffset := 39 + sessionIdLen
	if len(data) < 2 {
		return alertDecodeError
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return alertDecodeError
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.cipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
	}
	data = data[2+cipherSuiteLen:]
	bindersOffset += 2 + cipherSuiteLen
	if len(data) < 1 {
		return alertDecodeError
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return alertDecodeError
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]
	bindersOffset += 1 + compressionMethodsLen

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAndHashes = nil
	m.alpnProtocols = nil
	m.scts = false
	m.keyShares = nil
	m.supportedVersions = nil
	m.psks = nil
	m.pskKeyExchangeModes = nil
	m.earlyData = false
	m.shortHeaders = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return alertSuccess
	}
	if len(data) < 2 {
		return alertDecodeError
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	bindersOffset += 2
	if extensionsLength != len(data) {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		bindersOffset += 4
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return alertDecodeError
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return alertDecodeError
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return alertDecodeError
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return alertDecodeError
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return alertDecodeError
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.4
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return alertDecodeError
			}
			numCurves := l / 2
			m.supportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return alertDecodeError
			}
			l := int(data[0])
			if length != l+1 {
				return alertDecodeError
			}
			m.supportedPoints = make([]uint8, l)
			copy(m.supportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3
			if length < 2 || length&1 != 0 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			n := l / 2
			d := data[2:]
			m.signatureAndHashes = make([]signatureAndHash, n)
			for i := range m.signatureAndHashes {
				m.signatureAndHashes[i].hash = d[0]
				m.signatureAndHashes[i].signature = d[1]
				d = d[2:]
			}
		case extensionRenegotiationInfo:
			if length == 0 {
				return alertDecodeError
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return alertDecodeError
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true
		case extensionALPN:
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return alertDecodeError
				}
				m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionSCT:
			m.scts = true
			if length != 0 {
				return alertDecodeError
			}
		case extensionKeyShare:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.5
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			d := data[2:length]
			for len(d) != 0 {
				if len(d) < 4 {
					return alertDecodeError
				}
				dataLen := int(d[2])<<8 | int(d[3])
				if dataLen == 0 || 4+dataLen > len(d) {
					return alertDecodeError
				}
				m.keyShares = append(m.keyShares, keyShare{
					group: CurveID(d[0])<<8 | CurveID(d[1]),
					data:  d[4 : 4+dataLen],
				})
				d = d[4+dataLen:]
			}
		case extensionSupportedVersions:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.1
			if length < 1 {
				return alertDecodeError
			}
			l := int(data[0])
			if l%2 == 1 || length != l+1 {
				return alertDecodeError
			}
			n := l / 2
			d := data[1:]
			for i := 0; i < n; i++ {
				v := uint16(d[0])<<8 + uint16(d[1])
				m.supportedVersions = append(m.supportedVersions, v)
				d = d[2:]
			}
		case extensionPreSharedKey:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.6
			if length < 2 {
				return alertDecodeError
			}
			// Ensure this extension is the last one in the Client Hello
			if len(data) != length {
				return alertIllegalParameter
			}
			li := int(data[0])<<8 | int(data[1])
			if 2+li+2 > length {
				return alertDecodeError
			}
			d := data[2 : 2+li]
			bindersOffset += 2 + li
			for len(d) > 0 {
				if len(d) < 6 {
					return alertDecodeError
				}
				l := int(d[0])<<8 | int(d[1])
				if len(d) < 2+l+4 {
					return alertDecodeError
				}
				m.psks = append(m.psks, psk{
					identity: d[2 : 2+l],
					obfTicketAge: uint32(d[l+2])<<24 | uint32(d[l+3])<<16 |
						uint32(d[l+4])<<8 | uint32(d[l+5]),
				})
				d = d[2+l+4:]
			}
			lb := int(data[li+2])<<8 | int(data[li+3])
			d = data[2+li+2:]
			if lb != len(d) || lb == 0 {
				return alertDecodeError
			}
			i := 0
			for len(d) > 0 {
				if i >= len(m.psks) {
					return alertIllegalParameter
				}
				if len(d) < 1 {
					return alertDecodeError
				}
				l := int(d[0])
				if l > len(d)-1 {
					return alertDecodeError
				}
				if i >= len(m.psks) {
					return alertIllegalParameter
				}
				m.psks[i].binder = d[1 : 1+l]
				d = d[1+l:]
				i++
			}
			if i != len(m.psks) {
				return alertIllegalParameter
			}
			m.rawTruncated = m.raw[:bindersOffset]
		case extensionPSKKeyExchangeModes:
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])
			if length != l+1 {
				return alertDecodeError
			}
			m.pskKeyExchangeModes = data[1:length]
		case extensionEarlyData:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.8
			m.earlyData = true
			if length != 0 {
				return alertDecodeError
			}
		case extensionShortHeaders:
			// Experimental short headers extension
			m.shortHeaders = true
			if length != 0 {
				return alertDecodeError
			}
		}

		data = data[length:]
		bindersOffset += length
	}

	return alertSuccess
}

type serverHelloMsg struct {
	raw                          []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	scts                         [][]byte
	ticketSupported              bool
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocol                 string
}

func (m *serverHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverHelloMsg)
	if !ok {
		return false
	}

	if len(m.scts) != len(m1.scts) {
		return false
	}
	for i, sct := range m.scts {
		if !bytes.Equal(sct, m1.scts[i]) {
			return false
		}
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		m.cipherSuite == m1.cipherSuite &&
		m.compressionMethod == m1.compressionMethod &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		eqStrings(m.nextProtos, m1.nextProtos) &&
		m.ocspStapling == m1.ocspStapling &&
		m.ticketSupported == m1.ticketSupported &&
		m.secureRenegotiationSupported == m1.secureRenegotiationSupported &&
		bytes.Equal(m.secureRenegotiation, m1.secureRenegotiation) &&
		m.alpnProtocol == m1.alpnProtocol
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 38 + len(m.sessionId)
	numExtensions := 0
	extensionsLength := 0

	nextProtoLen := 0
	if m.nextProtoNeg {
		numExtensions++
		for _, v := range m.nextProtos {
			nextProtoLen += len(v)
		}
		nextProtoLen += len(m.nextProtos)
		extensionsLength += nextProtoLen
	}
	if m.ocspStapling {
		numExtensions++
	}
	if m.ticketSupported {
		numExtensions++
	}
	if m.secureRenegotiationSupported {
		extensionsLength += 1 + len(m.secureRenegotiation)
		numExtensions++
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		extensionsLength += 2 + 1 + alpnLen
		numExtensions++
	}
	sctLen := 0
	if len(m.scts) > 0 {
		for _, sct := range m.scts {
			sctLen += len(sct) + 2
		}
		extensionsLength += 2 + sctLen
		numExtensions++
	}

	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	z := x[39+len(m.sessionId):]
	z[0] = uint8(m.cipherSuite >> 8)
	z[1] = uint8(m.cipherSuite)
	z[2] = m.compressionMethod

	z = z[3:]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		z[2] = byte(nextProtoLen >> 8)
		z[3] = byte(nextProtoLen)
		z = z[4:]

		for _, v := range m.nextProtos {
			l := len(v)
			if l > 255 {
				l = 255
			}
			z[0] = byte(l)
			copy(z[1:], []byte(v[0:l]))
			z = z[1+l:]
		}
	}
	if m.ocspStapling {
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z = z[4:]
	}
	if m.ticketSupported {
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		z = z[4:]
	}
	if m.secureRenegotiationSupported {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = byte(len(m.secureRenegotiation) + 1)
		z[4] = byte(len(m.secureRenegotiation))
		z = z[5:]
		copy(z, m.secureRenegotiation)
		z = z[len(m.secureRenegotiation):]
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.alpnProtocol))
		z = z[7+alpnLen:]
	}
	if sctLen > 0 {
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		l := sctLen + 2
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z[4] = byte(sctLen >> 8)
		z[5] = byte(sctLen)

		z = z[6:]
		for _, sct := range m.scts {
			z[0] = byte(len(sct) >> 8)
			z[1] = byte(len(sct))
			copy(z[2:], sct)
			z = z[len(sct)+2:]
		}
	}

	m.raw = x

	return x
}

func (m *serverHelloMsg) unmarshal(data []byte) alert {
	if len(data) < 42 {
		return alertDecodeError
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return alertDecodeError
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return alertDecodeError
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.nextProtoNeg = false
	m.nextProtos = nil
	m.ocspStapling = false
	m.scts = nil
	m.ticketSupported = false
	m.alpnProtocol = ""

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return alertSuccess
	}
	if len(data) < 2 {
		return alertDecodeError
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return alertDecodeError
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return alertDecodeError
			}
			m.ocspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return alertDecodeError
			}
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if length == 0 {
				return alertDecodeError
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return alertDecodeError
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return alertDecodeError
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return alertDecodeError
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return alertDecodeError
			}
			m.alpnProtocol = string(d)
		case extensionSCT:
			d := data[:length]

			if len(d) < 2 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l {
				return alertDecodeError
			}
			if l == 0 {
				continue
			}

			m.scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return alertDecodeError
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if len(d) < sctLen {
					return alertDecodeError
				}
				m.scts = append(m.scts, d[:sctLen])
				d = d[sctLen:]
			}
		}
		data = data[length:]
	}

	return alertSuccess
}

type serverHelloMsg13 struct {
	raw          []byte
	vers         uint16
	random       []byte
	cipherSuite  uint16
	keyShare     keyShare
	psk          bool
	pskIdentity  uint16
	shortHeaders bool
}

func (m *serverHelloMsg13) equal(i interface{}) bool {
	m1, ok := i.(*serverHelloMsg13)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		m.cipherSuite == m1.cipherSuite &&
		m.keyShare.group == m1.keyShare.group &&
		bytes.Equal(m.keyShare.data, m1.keyShare.data) &&
		m.psk == m1.psk &&
		m.pskIdentity == m1.pskIdentity &&
		m.shortHeaders == m1.shortHeaders
}

func (m *serverHelloMsg13) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 38
	if m.keyShare.group != 0 {
		length += 8 + len(m.keyShare.data)
	}
	if m.psk {
		length += 6
	}
	if m.shortHeaders {
		length += 4
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(m.cipherSuite >> 8)
	x[39] = uint8(m.cipherSuite)

	z := x[42:]
	x[40] = uint8(len(z) >> 8)
	x[41] = uint8(len(z))

	if m.psk {
		z[0] = byte(extensionPreSharedKey >> 8)
		z[1] = byte(extensionPreSharedKey)
		z[3] = 2
		z[4] = byte(m.pskIdentity >> 8)
		z[5] = byte(m.pskIdentity)
		z = z[6:]
	}

	if m.keyShare.group != 0 {
		z[0] = uint8(extensionKeyShare >> 8)
		z[1] = uint8(extensionKeyShare)
		l := 4 + len(m.keyShare.data)
		z[2] = uint8(l >> 8)
		z[3] = uint8(l)
		z[4] = uint8(m.keyShare.group >> 8)
		z[5] = uint8(m.keyShare.group)
		l -= 4
		z[6] = uint8(l >> 8)
		z[7] = uint8(l)
		copy(z[8:], m.keyShare.data)
		z = z[8+l:]
	}
	if m.shortHeaders {
		z[0] = byte(extensionShortHeaders >> 8)
		z[1] = byte(extensionShortHeaders & 0xff)
		z[2] = 0
		z[3] = 0
		z = z[4:]
	}

	m.raw = x
	return x
}

func (m *serverHelloMsg13) unmarshal(data []byte) alert {
	if len(data) < 50 {
		return alertDecodeError
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	m.cipherSuite = uint16(data[38])<<8 | uint16(data[39])
	m.psk = false
	m.pskIdentity = 0
	m.shortHeaders = false

	extensionsLength := int(data[40])<<8 | int(data[41])
	data = data[42:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		default:
			return alertDecodeError
		case extensionPreSharedKey:
			if length != 2 {
				return alertDecodeError
			}
			m.psk = true
			m.pskIdentity = uint16(data[0])<<8 | uint16(data[1])
		case extensionKeyShare:
			if length < 2 {
				return alertDecodeError
			}
			m.keyShare.group = CurveID(data[0])<<8 | CurveID(data[1])
			if length-4 != int(data[2])<<8|int(data[3]) {
				return alertDecodeError
			}
			m.keyShare.data = data[4:length]
		case extensionShortHeaders:
			m.shortHeaders = true
		}
		data = data[length:]
	}

	return alertSuccess
}

type encryptedExtensionsMsg struct {
	raw          []byte
	alpnProtocol string
	earlyData    bool
}

func (m *encryptedExtensionsMsg) equal(i interface{}) bool {
	m1, ok := i.(*encryptedExtensionsMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.alpnProtocol == m1.alpnProtocol &&
		m.earlyData == m1.earlyData
}

func (m *encryptedExtensionsMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2

	if m.earlyData {
		length += 4
	}
	alpnLen := len(m.alpnProtocol)
	if alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		length += 2 + 2 + 2 + 1 + alpnLen
	}

	x := make([]byte, 4+length)
	x[0] = typeEncryptedExtensions
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	length -= 2
	x[4] = uint8(length >> 8)
	x[5] = uint8(length)

	z := x[6:]
	if alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.alpnProtocol))
		z = z[7+alpnLen:]
	}

	if m.earlyData {
		z[0] = byte(extensionEarlyData >> 8)
		z[1] = byte(extensionEarlyData)
		z = z[4:]
	}

	m.raw = x
	return x
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) alert {
	if len(data) < 6 {
		return alertDecodeError
	}
	m.raw = data

	m.alpnProtocol = ""
	m.earlyData = false

	extensionsLength := int(data[4])<<8 | int(data[5])
	data = data[6:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return alertDecodeError
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return alertDecodeError
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return alertDecodeError
			}
			m.alpnProtocol = string(d)
		case extensionEarlyData:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.8
			m.earlyData = true
		}

		data = data[length:]
	}

	return alertSuccess
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		eqByteSlices(m.certificates, m1.certificates)
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return
}

func (m *certificateMsg) unmarshal(data []byte) alert {
	if len(data) < 7 {
		return alertDecodeError
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return alertDecodeError
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return alertDecodeError
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return alertDecodeError
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return alertSuccess
}

type certificateEntry struct {
	data       []byte
	ocspStaple []byte
	sctList    [][]byte
}

type certificateMsg13 struct {
	raw            []byte
	requestContext []byte
	certificates   []certificateEntry
}

func (m *certificateMsg13) equal(i interface{}) bool {
	m1, ok := i.(*certificateMsg13)
	if !ok {
		return false
	}

	if len(m.certificates) != len(m1.certificates) {
		return false
	}
	for i, _ := range m.certificates {
		ok := bytes.Equal(m.certificates[i].data, m1.certificates[i].data)
		ok = ok && bytes.Equal(m.certificates[i].ocspStaple, m1.certificates[i].ocspStaple)
		ok = ok && eqByteSlices(m.certificates[i].sctList, m1.certificates[i].sctList)
		if !ok {
			return false
		}
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.requestContext, m1.requestContext)
}

func (m *certificateMsg13) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, cert := range m.certificates {
		i += len(cert.data)
		if cert.ocspStaple != nil {
			i += 8 + len(cert.ocspStaple)
		}
		if cert.sctList != nil {
			i += 4
			for _, sct := range cert.sctList {
				i += 2 + len(sct)
			}
		}
	}

	length := 3 + 3*len(m.certificates) + i
	length += 2 * len(m.certificates) // extensions
	length += 1 + len(m.requestContext)
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	z := x[4:]

	z[0] = byte(len(m.requestContext))
	copy(z[1:], m.requestContext)
	z = z[1+len(m.requestContext):]

	certificateOctets := len(z) - 3
	z[0] = uint8(certificateOctets >> 16)
	z[1] = uint8(certificateOctets >> 8)
	z[2] = uint8(certificateOctets)

	z = z[3:]
	for _, cert := range m.certificates {
		z[0] = uint8(len(cert.data) >> 16)
		z[1] = uint8(len(cert.data) >> 8)
		z[2] = uint8(len(cert.data))
		copy(z[3:], cert.data)
		z = z[3+len(cert.data):]

		extLenPos := z[:2]
		z = z[2:]

		extensionLen := 0
		if cert.ocspStaple != nil {
			stapleLen := 4 + len(cert.ocspStaple)
			z[0] = uint8(extensionStatusRequest >> 8)
			z[1] = uint8(extensionStatusRequest)
			z[2] = uint8(stapleLen >> 8)
			z[3] = uint8(stapleLen)

			stapleLen -= 4
			z[4] = statusTypeOCSP
			z[5] = uint8(stapleLen >> 16)
			z[6] = uint8(stapleLen >> 8)
			z[7] = uint8(stapleLen)
			copy(z[8:], cert.ocspStaple)
			z = z[8+stapleLen:]

			extensionLen += 8 + stapleLen
		}
		if cert.sctList != nil {
			z[0] = uint8(extensionSCT >> 8)
			z[1] = uint8(extensionSCT)
			sctLenPos := z[2:4]
			z = z[4:]
			extensionLen += 4

			sctLen := 0
			for _, sct := range cert.sctList {
				z[0] = uint8(len(sct) >> 8)
				z[1] = uint8(len(sct))
				copy(z[2:], sct)
				z = z[2+len(sct):]

				extensionLen += 2 + len(sct)
				sctLen += 2 + len(sct)
			}
			sctLenPos[0] = uint8(sctLen >> 8)
			sctLenPos[1] = uint8(sctLen)
		}
		extLenPos[0] = uint8(extensionLen >> 8)
		extLenPos[1] = uint8(extensionLen)
	}

	m.raw = x
	return
}

func (m *certificateMsg13) unmarshal(data []byte) alert {
	if len(data) < 5 {
		return alertDecodeError
	}

	m.raw = data

	ctxLen := data[4]
	if len(data) < int(ctxLen)+5+3 {
		return alertDecodeError
	}
	m.requestContext = data[5 : 5+ctxLen]

	d := data[5+ctxLen:]
	certsLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
	if uint32(len(d)) != certsLen+3 {
		return alertDecodeError
	}

	numCerts := 0
	d = d[3:]
	for certsLen > 0 {
		if len(d) < 4 {
			return alertDecodeError
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return alertDecodeError
		}
		d = d[3+certLen:]

		if len(d) < 2 {
			return alertDecodeError
		}
		extLen := uint16(d[0])<<8 | uint16(d[1])
		if uint16(len(d)) < 2+extLen {
			return alertDecodeError
		}
		d = d[2+extLen:]

		certsLen -= 3 + certLen + 2 + uint32(extLen)
		numCerts++
	}

	m.certificates = make([]certificateEntry, numCerts)
	d = data[8+ctxLen:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i].data = d[3 : 3+certLen]
		d = d[3+certLen:]

		extLen := uint16(d[0])<<8 | uint16(d[1])
		d = d[2:]
		for extLen > 0 {
			if extLen < 4 {
				return alertDecodeError
			}
			typ := uint16(d[0])<<8 | uint16(d[1])
			bodyLen := uint16(d[2])<<8 | uint16(d[3])
			if extLen < 4+bodyLen {
				return alertDecodeError
			}
			body := d[4 : 4+bodyLen]
			d = d[4+bodyLen:]
			extLen -= 4 + bodyLen

			switch typ {
			case extensionStatusRequest:
				if len(body) < 4 || body[0] != 0x01 {
					return alertDecodeError
				}
				ocspLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if len(body) != 4+ocspLen {
					return alertDecodeError
				}
				m.certificates[i].ocspStaple = body[4:]

			case extensionSCT:
				for len(body) > 0 {
					if len(body) < 2 {
						return alertDecodeError
					}
					sctLen := int(body[0]<<8) | int(body[1])
					if len(body) < 2+sctLen {
						return alertDecodeError
					}
					m.certificates[i].sctList = append(m.certificates[i].sctList, body[2:2+sctLen])
					body = body[2+sctLen:]
				}
			}
		}
	}

	return alertSuccess
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.key, m1.key)
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	m.key = data[4:]
	return alertSuccess
}

type certificateStatusMsg struct {
	raw        []byte
	statusType uint8
	response   []byte
}

func (m *certificateStatusMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateStatusMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.statusType == m1.statusType &&
		bytes.Equal(m.response, m1.response)
}

func (m *certificateStatusMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var x []byte
	if m.statusType == statusTypeOCSP {
		x = make([]byte, 4+4+len(m.response))
		x[0] = typeCertificateStatus
		l := len(m.response) + 4
		x[1] = byte(l >> 16)
		x[2] = byte(l >> 8)
		x[3] = byte(l)
		x[4] = statusTypeOCSP

		l -= 4
		x[5] = byte(l >> 16)
		x[6] = byte(l >> 8)
		x[7] = byte(l)
		copy(x[8:], m.response)
	} else {
		x = []byte{typeCertificateStatus, 0, 0, 1, m.statusType}
	}

	m.raw = x
	return x
}

func (m *certificateStatusMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 5 {
		return alertDecodeError
	}
	m.statusType = data[4]

	m.response = nil
	if m.statusType == statusTypeOCSP {
		if len(data) < 8 {
			return alertDecodeError
		}
		respLen := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		if uint32(len(data)) != 4+4+respLen {
			return alertDecodeError
		}
		m.response = data[8:]
	}
	return alertSuccess
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) equal(i interface{}) bool {
	_, ok := i.(*serverHelloDoneMsg)
	return ok
}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) alert {
	if len(data) != 4 {
		return alertDecodeError
	}
	return alertSuccess
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ciphertext, m1.ciphertext)
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return alertDecodeError
	}
	m.ciphertext = data[4:]
	return alertSuccess
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) equal(i interface{}) bool {
	m1, ok := i.(*finishedMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.verifyData, m1.verifyData)
}

func (m *finishedMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	x = make([]byte, 4+len(m.verifyData))
	x[0] = typeFinished
	x[3] = byte(len(m.verifyData))
	copy(x[4:], m.verifyData)
	m.raw = x
	return
}

func (m *finishedMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	m.verifyData = data[4:]
	return alertSuccess
}

type nextProtoMsg struct {
	raw   []byte
	proto string
}

func (m *nextProtoMsg) equal(i interface{}) bool {
	m1, ok := i.(*nextProtoMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.proto == m1.proto
}

func (m *nextProtoMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	l := len(m.proto)
	if l > 255 {
		l = 255
	}

	padding := 32 - (l+2)%32
	length := l + padding + 2
	x := make([]byte, length+4)
	x[0] = typeNextProtocol
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	y := x[4:]
	y[0] = byte(l)
	copy(y[1:], []byte(m.proto[0:l]))
	y = y[1+l:]
	y[0] = byte(padding)

	m.raw = x

	return x
}

func (m *nextProtoMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 5 {
		return alertDecodeError
	}
	data = data[4:]
	protoLen := int(data[0])
	data = data[1:]
	if len(data) < protoLen {
		return alertDecodeError
	}
	m.proto = string(data[0:protoLen])
	data = data[protoLen:]

	if len(data) < 1 {
		return alertDecodeError
	}
	paddingLen := int(data[0])
	data = data[1:]
	if len(data) != paddingLen {
		return alertDecodeError
	}

	return alertSuccess
}

type certificateRequestMsg struct {
	raw []byte
	// hasSignatureAndHash indicates whether this message includes a list
	// of signature and hash functions. This change was introduced with TLS
	// 1.2.
	hasSignatureAndHash bool

	certificateTypes       []byte
	signatureAndHashes     []signatureAndHash
	certificateAuthorities [][]byte
}

func (m *certificateRequestMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateRequestMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.certificateTypes, m1.certificateTypes) &&
		eqByteSlices(m.certificateAuthorities, m1.certificateAuthorities) &&
		eqSignatureAndHashes(m.signatureAndHashes, m1.signatureAndHashes)
}

func (m *certificateRequestMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.4
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	if m.hasSignatureAndHash {
		length += 2 + 2*len(m.signatureAndHashes)
	}

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

	if m.hasSignatureAndHash {
		n := len(m.signatureAndHashes) * 2
		y[0] = uint8(n >> 8)
		y[1] = uint8(n)
		y = y[2:]
		for _, sigAndHash := range m.signatureAndHashes {
			y[0] = sigAndHash.hash
			y[1] = sigAndHash.signature
			y = y[2:]
		}
	}

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	m.raw = x
	return
}

func (m *certificateRequestMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 5 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return alertDecodeError
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return alertDecodeError
	}

	data = data[numCertTypes:]

	if m.hasSignatureAndHash {
		if len(data) < 2 {
			return alertDecodeError
		}
		sigAndHashLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAndHashLen&1 != 0 {
			return alertDecodeError
		}
		if len(data) < int(sigAndHashLen) {
			return alertDecodeError
		}
		numSigAndHash := sigAndHashLen / 2
		m.signatureAndHashes = make([]signatureAndHash, numSigAndHash)
		for i := range m.signatureAndHashes {
			m.signatureAndHashes[i].hash = data[0]
			m.signatureAndHashes[i].signature = data[1]
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return alertDecodeError
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return alertDecodeError
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return alertDecodeError
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return alertDecodeError
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}

	if len(data) != 0 {
		return alertDecodeError
	}
	return alertSuccess
}

type certificateVerifyMsg struct {
	raw                 []byte
	hasSignatureAndHash bool
	signatureAndHash    signatureAndHash
	signature           []byte
}

func (m *certificateVerifyMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateVerifyMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.hasSignatureAndHash == m1.hasSignatureAndHash &&
		m.signatureAndHash.hash == m1.signatureAndHash.hash &&
		m.signatureAndHash.signature == m1.signatureAndHash.signature &&
		bytes.Equal(m.signature, m1.signature)
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.8
	siglength := len(m.signature)
	length := 2 + siglength
	if m.hasSignatureAndHash {
		length += 2
	}
	x = make([]byte, 4+length)
	x[0] = typeCertificateVerify
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	y := x[4:]
	if m.hasSignatureAndHash {
		y[0] = m.signatureAndHash.hash
		y[1] = m.signatureAndHash.signature
		y = y[2:]
	}
	y[0] = uint8(siglength >> 8)
	y[1] = uint8(siglength)
	copy(y[2:], m.signature)

	m.raw = x

	return
}

func (m *certificateVerifyMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 6 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	data = data[4:]
	if m.hasSignatureAndHash {
		m.signatureAndHash.hash = data[0]
		m.signatureAndHash.signature = data[1]
		data = data[2:]
	}

	if len(data) < 2 {
		return alertDecodeError
	}
	siglength := int(data[0])<<8 + int(data[1])
	data = data[2:]
	if len(data) != siglength {
		return alertDecodeError
	}

	m.signature = data

	return alertSuccess
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ticket, m1.ticket)
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc5077#section-3.3
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 10 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return alertDecodeError
	}

	m.ticket = data[10:]

	return alertSuccess
}

type newSessionTicketMsg13 struct {
	raw                []byte
	lifetime           uint32
	ageAdd             uint32
	ticket             []byte
	withEarlyDataInfo  bool
	maxEarlyDataLength uint32
}

func (m *newSessionTicketMsg13) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg13)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.lifetime == m1.lifetime &&
		m.ageAdd == m1.ageAdd &&
		bytes.Equal(m.ticket, m1.ticket) &&
		m.withEarlyDataInfo == m1.withEarlyDataInfo &&
		m.maxEarlyDataLength == m1.maxEarlyDataLength
}

func (m *newSessionTicketMsg13) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.6
	ticketLen := len(m.ticket)
	length := 12 + ticketLen
	if m.withEarlyDataInfo {
		length += 8
	}
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(m.lifetime >> 24)
	x[5] = uint8(m.lifetime >> 16)
	x[6] = uint8(m.lifetime >> 8)
	x[7] = uint8(m.lifetime)
	x[8] = uint8(m.ageAdd >> 24)
	x[9] = uint8(m.ageAdd >> 16)
	x[10] = uint8(m.ageAdd >> 8)
	x[11] = uint8(m.ageAdd)

	x[12] = uint8(ticketLen >> 8)
	x[13] = uint8(ticketLen)
	copy(x[14:], m.ticket)

	if m.withEarlyDataInfo {
		z := x[14+ticketLen:]
		z[1] = 8
		z[2] = uint8(extensionTicketEarlyDataInfo >> 8)
		z[3] = uint8(extensionTicketEarlyDataInfo)
		z[5] = 4
		z[6] = uint8(m.maxEarlyDataLength >> 24)
		z[7] = uint8(m.maxEarlyDataLength >> 16)
		z[8] = uint8(m.maxEarlyDataLength >> 8)
		z[9] = uint8(m.maxEarlyDataLength)
	}

	m.raw = x

	return
}

func (m *newSessionTicketMsg13) unmarshal(data []byte) alert {
	m.raw = data
	m.maxEarlyDataLength = 0
	m.withEarlyDataInfo = false

	if len(data) < 16 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	m.lifetime = uint32(data[4])<<24 | uint32(data[5])<<16 |
		uint32(data[6])<<8 | uint32(data[7])
	m.ageAdd = uint32(data[8])<<24 | uint32(data[9])<<16 |
		uint32(data[10])<<8 | uint32(data[11])

	ticketLen := int(data[12])<<8 + int(data[13])
	if 14+ticketLen > len(data) {
		return alertDecodeError
	}
	m.ticket = data[14 : 14+ticketLen]

	data = data[14+ticketLen:]
	extLen := int(data[0])<<8 + int(data[1])
	if extLen != len(data)-2 {
		return alertDecodeError
	}

	data = data[2:]
	for len(data) > 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extType := uint16(data[0])<<8 + uint16(data[1])
		length := int(data[2])<<8 + int(data[3])
		data = data[4:]

		switch extType {
		case extensionTicketEarlyDataInfo:
			if length != 4 {
				return alertDecodeError
			}
			m.withEarlyDataInfo = true
			m.maxEarlyDataLength = uint32(data[0])<<24 | uint32(data[1])<<16 |
				uint32(data[2])<<8 | uint32(data[3])
		}
		data = data[length:]
	}

	return alertSuccess
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() []byte {
	return []byte{typeHelloRequest, 0, 0, 0}
}

func (*helloRequestMsg) unmarshal(data []byte) alert {
	if len(data) != 4 {
		return alertDecodeError
	}
	return alertSuccess
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqCurveIDs(x, y []CurveID) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqStrings(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqByteSlices(x, y [][]byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if !bytes.Equal(v, y[i]) {
			return false
		}
	}
	return true
}

func eqSignatureAndHashes(x, y []signatureAndHash) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		v2 := y[i]
		if v.hash != v2.hash || v.signature != v2.signature {
			return false
		}
	}
	return true
}

func eqKeyShares(x, y []keyShare) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i].group != y[i].group {
			return false
		}
		if !bytes.Equal(x[i].data, y[i].data) {
			return false
		}
	}
	return true
}
