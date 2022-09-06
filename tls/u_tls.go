package tls

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const CIPHER_SUITE_GREASE uint16 = 0x0a0a
const GREASE_MAGIC uint16 = 0x7a7a

const (
	extensionPadding             uint16 = 0x0015
	extensionEMS                 uint16 = 0x0017
	extensionCompressCertificate uint16 = 0x001b
	extensionGrease              uint16 = 0x5a5a
	extensionGreaseLast          uint16 = 0x3a3a
	extensionApplicationSetting  uint16 = 0x4469
)

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

func transformClientHello(mRaw []byte) []byte {
	CIPHER_SUITES_UTLS_LITE := []uint16{
		CIPHER_SUITE_GREASE,
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
			fmt.Printf("Found alpn %v %v", extData, alpnData)
		}
	}

	// Pack all the goodies we extracted from the original ClientHello and
	// pack them up into a fresh new ClientHello byte array
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
			b.AddUint16(extensionGrease)
			b.AddUint16(0x0000)

			b.AddUint16(extensionServerName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(sniExtensionData)
			})

			b.AddUint16(extensionEMS)
			b.AddUint16(0x0000)

			b.AddUint16(extensionRenegotiationInfo)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(secureRenegotiationData)
			})

			b.AddUint16(extensionSupportedCurves)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(uint16(GREASE_MAGIC))
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

			/*
				if len(alpnData) > 0 {
					b.AddUint16(extensionALPN)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(alpnData)
					})
				}
			*/
			// Let's force ALPN for the moment
			b.AddUint16(extensionALPN)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("h2"))
					})
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("http/1.1"))
					})

				})
			})

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
					// TODO: parse and populate non-grease keyshares
					b.AddUint16(GREASE_MAGIC)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(1)
						b.AddUint8(0)
					})
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
					b.AddUint16(0xaaaa) // GREASE
					b.AddUint16(VersionTLS13)
					b.AddUint16(VersionTLS12)
				})
			})

			b.AddUint16(extensionCompressCertificate)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x0002) // brotli
				})
			})

			b.AddUint16(extensionApplicationSetting)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("h2"))
					})
				})
			})

			b.AddUint16(extensionGreaseLast)
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
