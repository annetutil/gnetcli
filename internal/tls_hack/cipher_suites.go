// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlshack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"hash"
)

// a keyAgreement implements the client and server side of a TLS key agreement
// protocol by generating and processing key exchange messages.
type keyAgreement interface {
	// On the server side, the first two methods are called in order.

	// In the case that the key agreement protocol doesn't use a
	// ServerKeyExchange message, generateServerKeyExchange can return nil,
	// nil.
	generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error)

	// On the client side, the next two methods are called in order.

	// This method may not be called if the server doesn't send a
	// ServerKeyExchange message.
	processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

const (
	// suiteRSA indicates that the cipher suite involves an RSA
	// signature and therefore may only be selected when the server's
	// certificate is RSA.
	suiteRSA = 1 << iota
	// suiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE
	// suiteECDSA indicates that the cipher suite involves an ECDSA
	// signature and therefore may only be selected when the server's
	// certificate is ECDSA. If this is not set then the cipher suite is
	// RSA based.
	suiteECDSA
	// suiteDHE indicates that the cipher suite involves Diffie-Hellman. This
	// means that a server should only use it if there's configured DH
	// parameters.
	suiteDHE
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384
	// Anonymous and PSK ciphersuites should not send or expect to receive certs
	suiteNoCerts
	// suiteDefaultOff indicates that this cipher suite is not included by
	// default.
	suiteDefaultOff
)

// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(version uint16, macKey []byte) macFunction
	aead   func(key, fixedNonce []byte) cipher.AEAD
}

var cipherSuites = []*cipherSuite{
	// Ciphersuite order is chosen so that ECDHE comes before plain RSA and
	// AEADs are the top preference.
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteRSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteRSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteRSA | suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE | suiteRSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE | suiteRSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteRSA | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteRSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA, suiteRSA | suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaKA, suiteRSA | suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, suiteRSA, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, suiteRSA, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE | suiteRSA, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, suiteRSA, cipher3DES, macSHA1, nil},

	// DHE PFS ciphersuites are disabled by default due to slowness
	{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, dheRSAKA, suiteDHE | suiteRSA | suiteTLS12 | suiteSHA384 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, dheRSAKA, suiteDHE | suiteRSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, dheRSAKA, suiteDHE | suiteRSA | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, dheRSAKA, suiteDHE | suiteRSA | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, dheRSAKA, suiteDHE | suiteRSA | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, dheRSAKA, suiteDHE | suiteRSA | suiteDefaultOff, cipherAES, macSHA1, nil},

	// PSK ciphersuites use preshared keys
	{TLS_RSA_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskRSAKA, suiteRSA | suiteTLS12 | suiteSHA384 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskRSAKA, suiteRSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskRSAKA, suiteRSA | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_RSA_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskRSAKA, suiteRSA | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_RSA_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskRSAKA, suiteRSA | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, dhePSKKA, suiteDHE | suiteNoCerts | suiteTLS12 | suiteSHA384 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, dhePSKKA, suiteDHE | suiteNoCerts | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, dhePSKKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, dhePSKKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_DHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, dhePSKKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskKA, suiteNoCerts | suiteTLS12 | suiteSHA384 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskKA, suiteNoCerts | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskKA, suiteNoCerts | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},

	// RC4-based cipher suites are disabled by default.
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, suiteRSA | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE | suiteRSA | suiteDefaultOff, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteDefaultOff, cipherRC4, macSHA1, nil},

	// DH_anon
	{TLS_DH_anon_WITH_AES_256_GCM_SHA384, 32, 0, 4, dheKA, suiteDHE | suiteNoCerts | suiteSHA384 | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DH_anon_WITH_AES_128_GCM_SHA256, 16, 0, 4, dheKA, suiteDHE | suiteNoCerts | suiteTLS12 | suiteDefaultOff, nil, nil, aeadAESGCM},
	{TLS_DH_anon_WITH_AES_256_CBC_SHA256, 32, 32, 16, dheKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_DH_anon_WITH_AES_128_CBC_SHA256, 16, 32, 16, dheKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA256, nil},
	{TLS_DH_anon_WITH_AES_256_CBC_SHA, 32, 20, 16, dheKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
	{TLS_DH_anon_WITH_AES_128_CBC_SHA, 16, 20, 16, dheKA, suiteDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
	// NOTE: Despite the name beginning with "ECDH_" (no E), the key used in
	// ECDH_anon is ephemeral just like the key in ECDHE_RSA and ECDHE_ECDSA.
	{TLS_ECDH_anon_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdhECDSAKA, suiteECDHE | suiteNoCerts | suiteDefaultOff, cipherAES, macSHA1, nil},
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(newConstantTimeHash(sha1.New), key)}
}

// macSHA256 returns a SHA-256 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func macSHA256(version uint16, key []byte) macFunction {
	return tls10MAC{hmac.New(sha256.New, key)}
}

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data, extra []byte) []byte
}

type aead interface {
	cipher.AEAD

	// explicitIVLen returns the number of bytes used by the explicit nonce
	// that is included in the record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

// fixedNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type fixedNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [12]byte
	aead  cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int        { return 8 }
func (f *fixedNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *fixedNonceAEAD) explicitNonceLen() int { return 8 }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], plaintext, additionalData)
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [12]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 }
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	//nolint:exhaustivestruct
	ret := &fixedNonceAEAD{aead: aead}
	copy(ret.nonce[:], fixedNonce)
	return ret
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

func (s ssl30MAC) Size() int {
	return s.h.Size()
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

// MAC does not offer constant timing guarantees for SSL v3.0, since it's deemed
// useless considering the similar, protocol-level POODLE vulnerability.
func (s ssl30MAC) MAC(digestBuf, seq, header, data, extra []byte) []byte {
	padLength := 48
	if s.h.Size() == 20 {
		padLength = 40
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(header[3:5])
	s.h.Write(data)
	digestBuf = s.h.Sum(digestBuf[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(digestBuf)
	return s.h.Sum(digestBuf[:0])
}

type constantTimeHash interface {
	hash.Hash
	ConstantTimeSum(b []byte) []byte
}

// cthWrapper wraps any hash.Hash that implements ConstantTimeSum, and replaces
// with that all calls to Sum. It's used to obtain a ConstantTimeSum-based HMAC.
type cthWrapper struct {
	h constantTimeHash
}

func (c *cthWrapper) Size() int                   { return c.h.Size() }
func (c *cthWrapper) BlockSize() int              { return c.h.BlockSize() }
func (c *cthWrapper) Reset()                      { c.h.Reset() }
func (c *cthWrapper) Write(p []byte) (int, error) { return c.h.Write(p) }
func (c *cthWrapper) Sum(b []byte) []byte         { return c.h.ConstantTimeSum(b) }

func newConstantTimeHash(h func() hash.Hash) func() hash.Hash {
	return func() hash.Hash {
		return &cthWrapper{h().(constantTimeHash)}
	}
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
	h hash.Hash
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

// MAC is guaranteed to take constant time, as long as
// len(seq)+len(header)+len(data)+len(extra) is constant. extra is not fed into
// the MAC, but is only provided to make the timing profile constant.
func (s tls10MAC) MAC(digestBuf, seq, header, data, extra []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	res := s.h.Sum(digestBuf[:0])
	if extra != nil {
		s.h.Write(extra)
	}
	return res
}

func rsaKA(version uint16) keyAgreement {
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &ecdheKeyAgreement{
		sigType: signatureECDSA,
		version: version,
	}
}
func ecdhECDSAKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &ecdheKeyAgreement{
		sigType:   signatureECDSA,
		version:   version,
		ignoreSig: true,
	}
}
func ecdheRSAKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &ecdheKeyAgreement{
		sigType: signatureRSA,
		version: version,
	}
}

func dheKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &dheKeyAgreement{}
}

// no dheECDSAKA because there's no implemented ciphersuite that uses DHE and ECDSA

func dheRSAKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &dheRsaKeyAgreement{
		sigType: signatureRSA,
		version: version,
	}
}

func pskKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &pskKeyAgreement{}
}

func pskRSAKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &pskRsaKeyAgreement{}
}

func dhePSKKA(version uint16) keyAgreement {
	//nolint:exhaustivestruct
	return &dhePskKeyAgreement{}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range cipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// Taken from http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
//
//nolint:st1003
const (
	TLS_RSA_WITH_RC4_128_SHA                  uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA             uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA              uint16 = 0x002f
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA          uint16 = 0x0033
	TLS_DH_anon_WITH_AES_128_CBC_SHA          uint16 = 0x0034
	TLS_RSA_WITH_AES_256_CBC_SHA              uint16 = 0x0035
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA          uint16 = 0x0039
	TLS_DH_anon_WITH_AES_256_CBC_SHA          uint16 = 0x003a
	TLS_RSA_WITH_AES_128_CBC_SHA256           uint16 = 0x003c
	TLS_RSA_WITH_AES_256_CBC_SHA256           uint16 = 0x003d
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       uint16 = 0x0067
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       uint16 = 0x006b
	TLS_DH_anon_WITH_AES_128_CBC_SHA256       uint16 = 0x006c
	TLS_DH_anon_WITH_AES_256_CBC_SHA256       uint16 = 0x006d
	TLS_PSK_WITH_AES_128_CBC_SHA              uint16 = 0x008C
	TLS_PSK_WITH_AES_256_CBC_SHA              uint16 = 0x008D
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA          uint16 = 0x0090
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA          uint16 = 0x0091
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA          uint16 = 0x0094
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA          uint16 = 0x0095
	TLS_RSA_WITH_AES_128_GCM_SHA256           uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384           uint16 = 0x009d
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       uint16 = 0x009e
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       uint16 = 0x009f
	TLS_DH_anon_WITH_AES_128_GCM_SHA256       uint16 = 0x00a6
	TLS_DH_anon_WITH_AES_256_GCM_SHA384       uint16 = 0x00a7
	TLS_PSK_WITH_AES_128_GCM_SHA256           uint16 = 0x00a8
	TLS_PSK_WITH_AES_256_GCM_SHA384           uint16 = 0x00a9
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256       uint16 = 0x00aa
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384       uint16 = 0x00ab
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256       uint16 = 0x00ac
	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384       uint16 = 0x00ad
	TLS_PSK_WITH_AES_128_CBC_SHA256           uint16 = 0x00ae
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256       uint16 = 0x00b2
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256       uint16 = 0x00b6
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA          uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA      uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA      uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA            uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA       uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA        uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA        uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256   uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256     uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305      uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305    uint16 = 0xcca9
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xccaa
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256     uint16 = 0xccab
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xccad
	TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xccae
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA        uint16 = 0xc019

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/rfc7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600
)
