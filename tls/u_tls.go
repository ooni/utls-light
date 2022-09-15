package tls

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/cryptobyte"
)

const (
	extensionPadding             uint16 = 21
	extensionEMS                 uint16 = 23
	extensionCompressCertificate uint16 = 27
	extensionApplicationSetting  uint16 = 0x4469
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

func (m *compressedCertificateMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
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

	m.raw = b.BytesOrPanic()
	return m.raw
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

// Taken from refraction-networking/utls
var extendedMasterSecretLabel = []byte("extended master secret")

// extendedMasterFromPreMasterSecret generates the master secret from the pre-master
// secret and session hash. See https://tools.ietf.org/html/rfc7627#section-4
func extendedMasterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret []byte, fh finishedHash) []byte {
	sessionHash := fh.Sum()
	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, extendedMasterSecretLabel, sessionHash)
	return masterSecret
}

func BoringPaddingStyle(unpaddedLen int) int {
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen
	}
	return 0
}

const (
	ssl_grease_cipher = iota
	ssl_grease_group
	ssl_grease_extension1
	ssl_grease_extension2
	ssl_grease_version
)

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

	// We need to parse the SNI field so we can re-use it in our own byte stream
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		panic("failed to parse extensions")
	}

	var secureRenegotiationData []byte
	var sniExtensionData []byte
	var sessionTicketData []byte
	var alpnData []byte
	var keyShares []keyShare
	var cookieData []byte
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&extData) {
			panic("failed to parse extension type")
		}
		if extension == extensionServerName {
			sniExtensionData = []byte(extData)
		} else if extension == extensionRenegotiationInfo {
			secureRenegotiationData = []byte(extData)
		} else if extension == extensionSessionTicket {
			sessionTicketData = []byte(extData)
		} else if extension == extensionALPN {
			alpnData = []byte(extData)
		} else if extension == extensionCookie {
			cookieData = []byte(extData)
		} else if extension == extensionKeyShare {
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

	// Pack all the goodies we extracted from the original ClientHello and
	// pack them up into a fresh new ClientHello byte array
	CIPHER_SUITES_UTLS_LITE := []uint16{
		BoringGrease(random, ssl_grease_cipher),
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
	SIGNATURE_ALGORITHMS_UTLS_LITE := []uint16{
		uint16(ECDSAWithP256AndSHA256),
		uint16(PSSWithSHA256),
		uint16(PKCS1WithSHA256),
		uint16(ECDSAWithP384AndSHA384),
		uint16(PSSWithSHA384),
		uint16(PKCS1WithSHA384),
		uint16(PSSWithSHA512),
		uint16(PKCS1WithSHA512),
	}
	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(header *cryptobyte.Builder) {
		header.AddUint16(vers)
		addBytesWithLength(header, random, 32)
		header.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionId)
		})
		header.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range CIPHER_SUITES_UTLS_LITE {
				b.AddUint16(suite)
			}
		})
		header.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]uint8{compressionNone})
		})

		header.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(BoringGrease(random, ssl_grease_extension1))
			b.AddUint16(0x0000)

			if len(sniExtensionData) > 0 {
				b.AddUint16(extensionServerName)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(sniExtensionData)
				})
			}

			b.AddUint16(extensionEMS)
			b.AddUint16(0x0000)

			b.AddUint16(extensionRenegotiationInfo)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(secureRenegotiationData)
			})

			b.AddUint16(extensionSupportedCurves)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(uint16(BoringGrease(random, ssl_grease_group)))
					b.AddUint16(uint16(X25519))
					b.AddUint16(uint16(CurveP256))
					b.AddUint16(uint16(CurveP384))
				})
			})

			b.AddUint16(extensionSupportedPoints)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(pointFormatUncompressed)
				})
			})

			b.AddUint16(extensionSessionTicket)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(sessionTicketData)
			})

			if len(alpnData) > 0 {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(alpnData)
				})
			}

			b.AddUint16(extensionStatusRequest)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(1)  // status_type = ocsp
				b.AddUint16(0) // empty responder_id_list
				b.AddUint16(0) // empty request_extensions
			})

			b.AddUint16(extensionSignatureAlgorithms)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, sigAlgo := range SIGNATURE_ALGORITHMS_UTLS_LITE {
						b.AddUint16(uint16(sigAlgo))
					}
				})
			})

			b.AddUint16(extensionSCT)
			b.AddUint16(0) // empty extension_data

			b.AddUint16(extensionKeyShare)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
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

			b.AddUint16(extensionPSKModes)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(1) // psk_dhe_ke
				})
			})

			b.AddUint16(extensionSupportedVersions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(BoringGrease(random, ssl_grease_version))
					b.AddUint16(VersionTLS13)
					b.AddUint16(VersionTLS12)
				})
			})

			if len(cookieData) > 0 {
				// RFC 8446, Section 4.2.2
				b.AddUint16(extensionCookie)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(cookieData)
				})
			}

			b.AddUint16(extensionCompressCertificate)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x0002) // brotli
				})
			})

			// This is disabled, because we don't support it, but nor does utls proper
			/*

				b.AddUint16(extensionApplicationSetting)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte("h2"))
						})
					})
				})
			*/

			b.AddUint16(BoringGrease(random, ssl_grease_extension2))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0)
			})

			chLen := len(header.BytesOrPanic()) + len(b.BytesOrPanic()) - 1
			paddingLen := BoringPaddingStyle(chLen)
			padding := make([]byte, paddingLen)
			b.AddUint16(extensionPadding)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(padding)
			})

		})
	})
	return b.BytesOrPanic()
}
