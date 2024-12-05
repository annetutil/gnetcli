// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlshack

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type clientHandshakeState struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

// c.out.Mutex <= L; c.handshakeMutex <= L.
func (c *Conn) clientHandshake() error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
		return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}

	//nolint:exhaustivestruct
	hello := &clientHelloMsg{
		vers:                         c.config.maxVersion(),
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(c.config.ServerName),
		supportedCurves:              c.config.curvePreferences(),
		supportedPoints:              []uint8{pointFormatUncompressed},
		nextProtoNeg:                 len(c.config.NextProtos) > 0,
		secureRenegotiationSupported: true,
		alpnProtocols:                c.config.NextProtos,
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteID := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteID {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteID)
			continue NextCipherSuite
		}
	}

	_, err := io.ReadFull(c.config.rand(), hello.random)
	if err != nil {
		errAlert := c.sendAlert(alertInternalError)
		if errAlert != nil {
			return errAlert
		}
		return errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.signatureAndHashes = supportedSignatureAlgorithms
	}

	var session *ClientSessionState
	var cacheKey string
	sessionCache := c.config.ClientSessionCache
	if c.config.SessionTicketsDisabled {
		sessionCache = nil
	}

	if sessionCache != nil {
		hello.ticketSupported = true
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if sessionCache != nil && c.handshakes == 0 {
		// Try to resume a previously negotiated TLS session, if
		// available.
		cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
		candidateSession, ok := sessionCache.Get(cacheKey)
		if ok {
			// Check that the ciphersuite/version used for the
			// previous session are still valid.
			cipherSuiteOk := false
			for _, id := range hello.cipherSuites {
				if id == candidateSession.cipherSuite {
					cipherSuiteOk = true
					break
				}
			}

			versOk := candidateSession.vers >= c.config.minVersion() &&
				candidateSession.vers <= c.config.maxVersion()
			if versOk && cipherSuiteOk {
				session = candidateSession
			}
		}
	}

	if session != nil {
		hello.sessionTicket = session.sessionTicket
		// A random session ID is used to detect when the
		// server accepted the ticket and is resuming a session
		// (see RFC 5077).
		hello.sessionID = make([]byte, 16)
		if _, err = io.ReadFull(c.config.rand(), hello.sessionID); err != nil {
			errAlert := c.sendAlert(alertInternalError)
			if errAlert != nil {
				return errAlert
			}
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return err
		}
		return unexpectedMessageError(serverHello, msg)
	}

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok || vers < VersionTLS10 {
		// TLS 1.0 is the minimum version supported as a client.
		err := c.sendAlert(alertProtocolVersion)
		if err != nil {
			return err
		}
		return fmt.Errorf("tls: server selected unsupported protocol version %x", serverHello.vers)
	}
	c.vers = vers
	c.haveVers = true

	suite := mutualCipherSuite(hello.cipherSuites, serverHello.cipherSuite)
	if suite == nil {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return err
		}
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	//nolint:exhaustivestruct
	hs := &clientHandshakeState{
		c:            c,
		serverHello:  serverHello,
		hello:        hello,
		suite:        suite,
		finishedHash: newFinishedHash(c.vers, suite),
		session:      session,
	}

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	_, err = hs.finishedHash.Write(hs.hello.marshal())
	if err != nil {
		return err
	}
	_, err = hs.finishedHash.Write(hs.serverHello.marshal())
	if err != nil {
		return err
	}

	c.buffering = true
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	c.didResume = isResume
	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok {
		// if should expect cert, this is the wrong type
		if hs.suite.flags&suiteNoCerts == 0 {
			err := c.sendAlert(alertUnexpectedMessage)
			if err != nil {
				return err
			}
			return unexpectedMessageError(certMsg, msg)
		}
	} else if len(certMsg.certificates) == 0 {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return err
		}
		return unexpectedMessageError(certMsg, msg)
	} else {
		// Expected a cert and got one
		_, err = hs.finishedHash.Write(certMsg.marshal())
		if err != nil {
			return err
		}

		if c.handshakes == 0 {
			// If this is the first handshake on a connection, process and
			// (optionally) verify the server's certificates.
			certs := make([]*x509.Certificate, len(certMsg.certificates))
			for i, asn1Data := range certMsg.certificates {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					errAlert := c.sendAlert(alertBadCertificate)
					if errAlert != nil {
						return errAlert
					}
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}

			if !c.config.InsecureSkipVerify {
				opts := x509.VerifyOptions{
					Roots:         c.config.RootCAs,
					CurrentTime:   c.config.time(),
					DNSName:       c.config.ServerName,
					Intermediates: x509.NewCertPool(),
				}

				for i, cert := range certs {
					if i == 0 {
						continue
					}
					opts.Intermediates.AddCert(cert)
				}
				c.verifiedChains, err = certs[0].Verify(opts)
				if err != nil {
					err := c.sendAlert(alertBadCertificate)
					if err != nil {
						return err
					}
					return err
				}
			}

			if c.config.VerifyPeerCertificate != nil {
				if err := c.config.VerifyPeerCertificate(certMsg.certificates, c.verifiedChains); err != nil {
					err := c.sendAlert(alertBadCertificate)
					if err != nil {
						return err
					}
					return err
				}
			}

			switch certs[0].PublicKey.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey:
				break
			default:
				err := c.sendAlert(alertUnsupportedCertificate)
				if err != nil {
					return err
				}
				return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
			}

			c.peerCertificates = certs
		} else {
			// This is a renegotiation handshake. We require that the
			// server's identity (i.e. leaf certificate) is unchanged and
			// thus any previous trust decision is still valid.
			//
			// See https://mitls.org/pages/attacks/3SHAKE for the
			// motivation behind this requirement.
			if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
				err := c.sendAlert(alertBadCertificate)
				if err != nil {
					return err
				}
				return errors.New("tls: server's identity changed during renegotiation")
			}
		}
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var firstPeerCert *x509.Certificate
	if len(c.peerCertificates) > 0 {
		firstPeerCert = c.peerCertificates[0]
	}

	if hs.serverHello.ocspStapling {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		cs, ok := msg.(*certificateStatusMsg)
		if !ok {
			err := c.sendAlert(alertUnexpectedMessage)
			if err != nil {
				return err
			}
			return unexpectedMessageError(cs, msg)
		}
		_, err := hs.finishedHash.Write(cs.marshal())
		if err != nil {
			return err
		}

		if cs.statusType == statusTypeOCSP {
			c.ocspResponse = cs.response
		}
	}

	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		_, err := hs.finishedHash.Write(skx.marshal())
		if err != nil {
			return err
		}
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, firstPeerCert, skx)
		if err != nil {
			err := c.sendAlert(alertUnexpectedMessage)
			if err != nil {
				return err
			}
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		_, err := hs.finishedHash.Write(certReq.marshal())
		if err != nil {
			return err
		}

		if chainToSend, err = hs.getCertificate(certReq); err != nil {
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return err
		}
		return unexpectedMessageError(shd, msg)
	}
	_, err = hs.finishedHash.Write(shd.marshal())
	if err != nil {
		return err
	}

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		_, err := hs.finishedHash.Write(certMsg.marshal())
		if err != nil {
			return err
		}
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, firstPeerCert)

	if err != nil {
		err := c.sendAlert(alertInternalError)
		if err != nil {
			return err
		}
		return err
	}
	if ckx != nil {
		_, err := hs.finishedHash.Write(ckx.marshal())
		if err != nil {
			return err
		}
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		//nolint:exhaustivestruct
		certVerify := &certificateVerifyMsg{
			hasSignatureAndHash: c.vers >= VersionTLS12,
		}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var signatureType uint8
		switch key.Public().(type) {
		case *ecdsa.PublicKey:
			signatureType = signatureECDSA
		case *rsa.PublicKey:
			signatureType = signatureRSA
		default:
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return fmt.Errorf("tls: failed to sign handshake with client certificate: unknown client certificate key type: %T", key)
		}

		certVerify.signatureAndHash, err = hs.finishedHash.selectClientCertSignatureAlgorithm(certReq.signatureAndHashes, signatureType)
		if err != nil {
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return err
		}
		digest, hashFunc, err := hs.finishedHash.hashForClientCertificate(certVerify.signatureAndHash, hs.masterSecret)
		if err != nil {
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return err
		}
		certVerify.signature, err = key.Sign(c.config.rand(), digest, hashFunc)
		if err != nil {
			err := c.sendAlert(alertInternalError)
			if err != nil {
				return err
			}
			return err
		}

		_, err = hs.finishedHash.Write(certVerify.marshal())
		if err != nil {
			return err
		}
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(hs.hello.random, hs.masterSecret); err != nil {
		errAlert := c.sendAlert(alertInternalError)
		if errAlert != nil {
			return errAlert
		}
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionID then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionID != nil &&
		bytes.Equal(hs.serverHello.sessionID, hs.hello.sessionID)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if hs.serverHello.compressionMethod != compressionNone {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			err := c.sendAlert(alertHandshakeFailure)
			if err != nil {
				return false, err
			}
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			err := c.sendAlert(alertHandshakeFailure)
			if err != nil {
				return false, err
			}
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}
	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return false, err
		}
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	err := c.readRecord(recordTypeChangeCipherSpec)
	if err != nil {
		return err
	}
	if c.in.err != nil {
		return c.in.err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return err
		}
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return err
		}
		return errors.New("tls: server's Finished message was incorrect")
	}
	_, err = hs.finishedHash.Write(serverFinished.marshal())
	if err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		err := c.sendAlert(alertUnexpectedMessage)
		if err != nil {
			return err
		}
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	_, err = hs.finishedHash.Write(sessionTicketMsg.marshal())
	if err != nil {
		return err
	}

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		_, err := hs.finishedHash.Write(nextProto.marshal())
		if err != nil {
			return err
		}
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	_, err := hs.finishedHash.Write(finished.marshal())
	if err != nil {
		return err
	}
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// tls11SignatureSchemes contains the signature schemes that we synthesise for
// a TLS <= 1.1 connection, based on the supported certificate types.
var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}

const (
	// tls11SignatureSchemesNumECDSA is the number of initial elements of
	// tls11SignatureSchemes that use ECDSA.
	tls11SignatureSchemesNumECDSA = 3
	// tls11SignatureSchemesNumRSA is the number of trailing elements of
	// tls11SignatureSchemes that use RSA.
	tls11SignatureSchemesNumRSA = 4
)

func (hs *clientHandshakeState) getCertificate(certReq *certificateRequestMsg) (*Certificate, error) {
	c := hs.c

	var rsaAvail, ecdsaAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecdsaAvail = true
		}
	}

	if c.config.GetClientCertificate != nil {
		var signatureSchemes []SignatureScheme

		if !certReq.hasSignatureAndHash {
			// Prior to TLS 1.2, the signature schemes were not
			// included in the certificate request message. In this
			// case we use a plausible list based on the acceptable
			// certificate types.
			signatureSchemes = tls11SignatureSchemes
			if !ecdsaAvail {
				signatureSchemes = signatureSchemes[tls11SignatureSchemesNumECDSA:]
			}
			if !rsaAvail {
				signatureSchemes = signatureSchemes[:len(signatureSchemes)-tls11SignatureSchemesNumRSA]
			}
		} else {
			signatureSchemes = make([]SignatureScheme, 0, len(certReq.signatureAndHashes))
			for _, sah := range certReq.signatureAndHashes {
				signatureSchemes = append(signatureSchemes, SignatureScheme(sah.hash)<<8+SignatureScheme(sah.signature))
			}
		}

		return c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    certReq.certificateAuthorities,
			SignatureSchemes: signatureSchemes,
		})
	}

	// RFC 4346 on the certificateAuthorities field: A list of the
	// distinguished names of acceptable certificate authorities.
	// These distinguished names may specify a desired
	// distinguished name for a root CA or for a subordinate CA;
	// thus, this message can be used to describe both known roots
	// and a desired authorization space. If the
	// certificate_authorities list is empty then the client MAY
	// send any certificate of the appropriate
	// ClientCertificateType, unless there is some external
	// arrangement to the contrary.

	// We need to search our list of client certs for one
	// where SignatureAlgorithm is acceptable to the server and the
	// Issuer is in certReq.certificateAuthorities
findCert:
	for i, chain := range c.config.Certificates {
		if !rsaAvail && !ecdsaAvail {
			continue
		}

		for j, cert := range chain.Certificate {
			x509Cert := chain.Leaf
			// parse the certificate if this isn't the leaf
			// node, or if chain.Leaf was nil
			if j != 0 || x509Cert == nil {
				var err error
				if x509Cert, err = x509.ParseCertificate(cert); err != nil {
					errAlert := c.sendAlert(alertInternalError)
					if errAlert != nil {
						return nil, errAlert
					}
					return nil, errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
				}
			}

			switch {
			case rsaAvail && x509Cert.PublicKeyAlgorithm == x509.RSA:
			case ecdsaAvail && x509Cert.PublicKeyAlgorithm == x509.ECDSA:
			default:
				continue findCert
			}

			if len(certReq.certificateAuthorities) == 0 {
				// they gave us an empty list, so just take the
				// first cert from c.config.Certificates
				return &chain, nil
			}

			for _, ca := range certReq.certificateAuthorities {
				if bytes.Equal(x509Cert.RawIssuer, ca) {
					return &chain, nil
				}
			}
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// mutualProtocol finds the mutual Next Protocol Negotiation or ALPN protocol
// given list of possible protocols and a list of the preference order. The
// first list must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
func mutualProtocol(protos, preferenceProtos []string) (string, bool) {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s, false
			}
		}
	}

	return protos[0], true
}

// hostnameInSNI converts name into an approriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See https://tools.ietf.org/html/rfc6066#section-3.
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
