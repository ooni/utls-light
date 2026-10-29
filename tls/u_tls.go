package tls

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"io"
	mathrand "math/rand/v2"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/cryptobyte"
)

const (
	extensionCompressCertificate uint16 = 27
)

const (
	typeCompressedCertificate uint8 = 25
)

const (
	certCompressionZlib   uint16 = 0x0001
	certCompressionBrotli uint16 = 0x0002
	certCompressionZstd   uint16 = 0x0003
)

// Taken from refraction-networking/utls
// Only implemented client-side, for server certificates.
// Alternate certificate message formats (https://datatracker.ietf.org/doc/html/rfc7250) are not
// supported.
// https://datatracker.ietf.org/doc/html/rfc8879
type compressedCertificateMsg struct {
	raw []byte

	algorithm                    uint16
	uncompressedLength           uint32 // uint24
	compressedCertificateMessage []byte
}

func (m *compressedCertificateMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCompressedCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.algorithm)
		b.AddUint24(m.uncompressedLength)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressedCertificateMessage)
		})
	})

	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *compressedCertificateMsg) decompressCert() (*certificateMsgTLS13, error) {
	var (
		decompressed io.Reader
		compressed   = bytes.NewReader(m.compressedCertificateMessage)
	)

	// We don't check if the certificate is compressed in a way we
	// advertised support for and we can't send in-spec error messages
	// because we don't have acceess to the handshake state.
	switch m.algorithm {
	case certCompressionBrotli:
		decompressed = brotli.NewReader(compressed)

	case certCompressionZlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("failed to open zlib reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	case certCompressionZstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("failed to open zstd reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	default:
		return nil, fmt.Errorf("unsupported algorithm (%d)", m.algorithm)
	}

	rawMsg := make([]byte, m.uncompressedLength+4) // +4 for message type and uint24 length field
	rawMsg[0] = typeCertificate
	rawMsg[1] = uint8(m.uncompressedLength >> 16)
	rawMsg[2] = uint8(m.uncompressedLength >> 8)
	rawMsg[3] = uint8(m.uncompressedLength)

	n, err := decompressed.Read(rawMsg[4:])
	if err != nil {
		return nil, err
	}
	if n < len(rawMsg)-4 {
		// If, after decompression, the specified length does not match the actual length, the party
		// receiving the invalid message MUST abort the connection with the "bad_certificate" alert.
		// https://datatracker.ietf.org/doc/html/rfc8879#section-4
		return nil, fmt.Errorf("decompressed len (%d) does not match specified len (%d)", n, m.uncompressedLength)
	}
	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawMsg) {
		return nil, alertUnexpectedMessage
	}
	return certMsg, nil
}

func (m *compressedCertificateMsg) unmarshal(data []byte) bool {
	*m = compressedCertificateMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.algorithm) ||
		!s.ReadUint24(&m.uncompressedLength) ||
		!readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	return true
}

// Chrome's cipher suites and signature schemes, in its order and without
// GREASE. The client accepts what the server picks from these.
var chromeCipherSuites = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
}

var chromeSignatureAlgorithms = []SignatureScheme{
	MLDSA44,
	MLDSA65,
	MLDSA87,
	ECDSAWithP256AndSHA256,
	PSSWithSHA256,
	PKCS1WithSHA256,
	ECDSAWithP384AndSHA384,
	PSSWithSHA384,
	PKCS1WithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA512,
}

// chromeSupportedGroups are Chrome's, after GREASE. Go's key shares, which
// the rewrite keeps, are X25519MLKEM768 and X25519, in that order.
var chromeSupportedGroups = []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384}

// chromeTrustAnchorIDs are the trust anchor IDs (draft-ietf-tls-trust-anchor-ids)
// Chrome 155 and 156 send, in their order, from Chrome's root store.
var chromeTrustAnchorIDs = [][]byte{
	{0x82, 0xdf, 0x13, 0x02, 0x01},
	{0x82, 0xdf, 0x13, 0x02, 0x06},
	{0x82, 0xdf, 0x13, 0x02, 0x0d},
	{0x82, 0xdf, 0x13, 0x02, 0x0e},
	{0x82, 0xdf, 0x13, 0x02, 0x0f},
	{0x82, 0xdf, 0x13, 0x02, 0x12},
	{0x82, 0xdf, 0x13, 0x02, 0x13},
	{0x82, 0xdf, 0x13, 0x02, 0x14},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
	{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
	{0xd6, 0x79, 0x09, 0x01},
	{0xd6, 0x79, 0x09, 0x04},
	{0xd6, 0x79, 0x09, 0x05},
	{0xd6, 0x79, 0x09, 0x06},
	{0xd6, 0x79, 0x09, 0x07},
	{0xd6, 0x79, 0x09, 0x08},
	{0xd6, 0x79, 0x09, 0x0a},
	{0xd6, 0x79, 0x09, 0x0b},
	{0xd6, 0x79, 0x09, 0x0c},
	{0xd6, 0x79, 0x09, 0x0d},
	{0xd6, 0x79, 0x09, 0x0f},
}

const (
	extensionTrustAnchors        uint16 = 0xca34
	extensionApplicationSettings uint16 = 17613 // ALPS, Chrome's new codepoint
)

// GREASE indices, as BoringSSL's ssl_grease_index_t
const (
	ssl_grease_cipher = iota
	ssl_grease_group
	ssl_grease_extension1
	ssl_grease_extension2
	ssl_grease_version
	ssl_grease_ticket_extension
	ssl_grease_ech_config_id
	ssl_grease_sigalg
)

// BoringGrease returns the GREASE value BoringSSL would use at index,
// seeded with the ClientHello's random.
func BoringGrease(clientRandom []byte, index int) uint16 {
	var ret uint16
	ret = uint16(clientRandom[index])
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	// The two fake extensions must not have the same value. GREASE values are
	// of the form 0x1a1a, 0x2a2a, 0x3a3a, etc., so XOR to generate a different
	// one.
	if index == ssl_grease_extension2 && ret == BoringGrease(clientRandom, ssl_grease_extension1) {
		ret ^= 0x1010
	}
	return ret
}

// helloRand returns a generator seeded with the ClientHello's random, so
// that marshalling the same ClientHello twice gives the same bytes.
func helloRand(clientRandom []byte) *mathrand.Rand {
	seed := sha256.Sum256(append([]byte("utls-light chrome"), clientRandom...))
	return mathrand.New(mathrand.NewChaCha8(seed))
}

// helloExtension is one ClientHello extension, as on the wire.
type helloExtension struct {
	typ  uint16
	data []byte
}

func buildBytes(fn func(b *cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	fn(&b)
	return b.BytesOrPanic()
}

// transformClientHello rewrites the ClientHello Go marshalled into the one
// Chrome 156 sends: its cipher suites, extensions and GREASE, in Chrome's
// shuffled order. It keeps Go's random, session ID, SNI, ALPN, key shares,
// renegotiation info, session ticket, cookie and pre-shared key.
func transformClientHello(mRaw []byte, noGreaseKeyshare bool) []byte {
	vers := uint16(0)
	random := make([]byte, 32)
	sessionId := make([]byte, 32)

	s := cryptobyte.String(mRaw)
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&vers) || !s.ReadBytes(&random, 32) ||
		!readUint8LengthPrefixed(&s, &sessionId) {
		panic("failed to read header")
	}

	// Ignore all the original cipher suites and compression methods
	var origCipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&origCipherSuites) {
		panic("failed to read ciphersuites")
	}
	var origCompressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&origCompressionMethods) {
		panic("failed to read compression method")
	}

	if s.Empty() {
		panic("no extension data present, panic early")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		panic("failed to parse extensions")
	}

	// The extensions whose contents we keep from Go's ClientHello
	kept := map[uint16][]byte{}
	var keyShares []keyShare
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&extData) {
			panic("failed to parse extension type")
		}
		switch extension {
		case extensionServerName, extensionRenegotiationInfo, extensionSessionTicket,
			extensionALPN, extensionCookie, extensionPreSharedKey, extensionEarlyData:
			kept[extension] = []byte(extData)
		case extensionKeyShare:
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				panic("failed to read keyshare information")
			}
			for !clientShares.Empty() {
				var ks keyShare
				if !clientShares.ReadUint16((*uint16)(&ks.group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.data) ||
					len(ks.data) == 0 {
					panic("failed to load keyshare information")
				}
				keyShares = append(keyShares, ks)
			}
		}
	}

	rnd := helloRand(random)
	var exts []helloExtension
	add := func(typ uint16, fn func(b *cryptobyte.Builder)) {
		exts = append(exts, helloExtension{typ, buildBytes(fn)})
	}
	addKept := func(typ uint16) {
		if data, ok := kept[typ]; ok {
			exts = append(exts, helloExtension{typ, data})
		}
	}

	addKept(extensionServerName)
	add(extensionExtendedMasterSecret, func(b *cryptobyte.Builder) {})
	add(extensionRenegotiationInfo, func(b *cryptobyte.Builder) {
		if data, ok := kept[extensionRenegotiationInfo]; ok {
			b.AddBytes(data)
		} else {
			b.AddUint8(0) // empty renegotiated_connection
		}
	})
	add(extensionSupportedCurves, func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(BoringGrease(random, ssl_grease_group))
			for _, group := range chromeSupportedGroups {
				b.AddUint16(uint16(group))
			}
		})
	})
	add(extensionSupportedPoints, func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(pointFormatUncompressed)
		})
	})
	add(extensionSessionTicket, func(b *cryptobyte.Builder) {
		b.AddBytes(kept[extensionSessionTicket])
	})
	addKept(extensionALPN)
	add(extensionStatusRequest, func(b *cryptobyte.Builder) {
		b.AddUint8(1)  // status_type = ocsp
		b.AddUint16(0) // empty responder_id_list
		b.AddUint16(0) // empty request_extensions
	})
	add(extensionSignatureAlgorithms, func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(BoringGrease(random, ssl_grease_sigalg))
			for _, sigAlgo := range chromeSignatureAlgorithms {
				b.AddUint16(uint16(sigAlgo))
			}
		})
	})
	add(extensionSCT, func(b *cryptobyte.Builder) {})
	add(extensionKeyShare, func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if !noGreaseKeyshare {
				b.AddUint16(BoringGrease(random, ssl_grease_group))
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0)
				})
			}
			for _, ks := range keyShares {
				b.AddUint16(uint16(ks.group))
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(ks.data)
				})
			}
		})
	})
	add(extensionPSKModes, func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(pskModeDHE)
		})
	})
	add(extensionSupportedVersions, func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(BoringGrease(random, ssl_grease_version))
			b.AddUint16(VersionTLS13)
			b.AddUint16(VersionTLS12)
		})
	})
	addKept(extensionCookie)
	addKept(extensionEarlyData)
	add(extensionCompressCertificate, func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(certCompressionBrotli)
		})
	})
	if offersH2(kept[extensionALPN]) {
		add(extensionApplicationSettings, func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte("h2"))
				})
			})
		})
	}
	add(extensionTrustAnchors, func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range chromeTrustAnchorIDs {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(id)
				})
			}
		})
	})
	add(extensionEncryptedClientHello, func(b *cryptobyte.Builder) {
		greaseECH(b, rnd)
	})

	// Chrome shuffles every extension but GREASE and pre_shared_key
	rnd.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })
	exts = append([]helloExtension{{BoringGrease(random, ssl_grease_extension1), nil}}, exts...)
	exts = append(exts, helloExtension{BoringGrease(random, ssl_grease_extension2), []byte{0}})
	if data, ok := kept[extensionPreSharedKey]; ok {
		exts = append(exts, helloExtension{extensionPreSharedKey, data})
	}

	return buildBytes(func(b *cryptobyte.Builder) {
		b.AddUint8(typeClientHello)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(vers)
			addBytesWithLength(b, random, 32)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(sessionId)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(BoringGrease(random, ssl_grease_cipher))
				for _, suite := range chromeCipherSuites {
					b.AddUint16(suite)
				}
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(compressionNone)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ext := range exts {
					b.AddUint16(ext.typ)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(ext.data)
					})
				}
			})
		})
	})
}

// offersH2 tells whether an ALPN extension's data lists h2.
func offersH2(alpn []byte) bool {
	s := cryptobyte.String(alpn)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return false
	}
	for !list.Empty() {
		var proto cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&proto) {
			return false
		}
		if string(proto) == "h2" {
			return true
		}
	}
	return false
}

// greaseECH writes BoringSSL's GREASE encrypted_client_hello: an outer
// ECH with HKDF-SHA256 and AES-128-GCM, a random config ID and X25519 key,
// and a random payload of 144, 176, 208 or 240 bytes.
func greaseECH(b *cryptobyte.Builder, rnd *mathrand.Rand) {
	fill := func(n int) []byte {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(rnd.Uint32())
		}
		return buf
	}
	b.AddUint8(0)       // outer
	b.AddUint16(0x0001) // HKDF-SHA256
	b.AddUint16(0x0001) // AES-128-GCM
	b.AddUint8(byte(rnd.Uint32()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(fill(32))
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(fill(128 + 32*rnd.IntN(4) + 16))
	})
}

// clientEncryptedExtensionsMsg is the client's EncryptedExtensions, which
// carries its ALPS settings (draft-vvv-tls-alps). Like Chrome without
// custom settings, we send none.
type clientEncryptedExtensionsMsg struct {
	raw []byte
}

func (m *clientEncryptedExtensionsMsg) marshal() ([]byte, error) {
	if m.raw != nil {
		return m.raw, nil
	}
	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(extensionApplicationSettings)
			b.AddUint16(0) // empty settings
		})
	})
	var err error
	m.raw, err = b.Bytes()
	return m.raw, err
}

func (m *clientEncryptedExtensionsMsg) unmarshal(data []byte) bool {
	m.raw = data
	return true
}
