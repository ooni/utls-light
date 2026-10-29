package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// chromeHello is a ClientHello reduced to what Chrome keeps fixed: no
// GREASE values, randomness, key material, SNI or extension order.
type chromeHello struct {
	ciphers    []uint16
	extensions map[uint16][]byte // contents, where they're fixed
	echPayload int
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func dropGREASE(s cryptobyte.String, prefixLen int) []byte {
	var list cryptobyte.String
	ok := false
	if prefixLen == 1 {
		ok = s.ReadUint8LengthPrefixed(&list)
	} else {
		ok = s.ReadUint16LengthPrefixed(&list)
	}
	if !ok {
		return nil
	}
	var out []byte
	for !list.Empty() {
		var v uint16
		list.ReadUint16(&v)
		if !isGREASE(v) {
			out = append(out, byte(v>>8), byte(v))
		}
	}
	return out
}

func parseChromeHello(t *testing.T, record []byte) *chromeHello {
	t.Helper()
	s := cryptobyte.String(record)
	var hs cryptobyte.String
	var typ uint8
	if !s.Skip(5) || !s.ReadUint8(&typ) || typ != typeClientHello || !s.ReadUint24LengthPrefixed(&hs) {
		t.Fatal("not a ClientHello record")
	}
	var random, sid, ciphers, comp, exts cryptobyte.String
	if !hs.Skip(2) || !hs.ReadBytes((*[]byte)(&random), 32) || !hs.ReadUint8LengthPrefixed(&sid) ||
		!hs.ReadUint16LengthPrefixed(&ciphers) || !hs.ReadUint8LengthPrefixed(&comp) ||
		!hs.ReadUint16LengthPrefixed(&exts) {
		t.Fatal("bad ClientHello")
	}
	h := &chromeHello{extensions: map[uint16][]byte{}}
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		if !isGREASE(c) {
			h.ciphers = append(h.ciphers, c)
		}
	}
	for !exts.Empty() {
		var ext uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&ext) || !exts.ReadUint16LengthPrefixed(&data) {
			t.Fatal("bad extension")
		}
		if isGREASE(ext) {
			continue
		}
		switch ext {
		case extensionServerName: // the host
			h.extensions[ext] = nil
		case extensionSupportedCurves, extensionSignatureAlgorithms:
			h.extensions[ext] = dropGREASE(data, 2)
		case extensionSupportedVersions:
			h.extensions[ext] = dropGREASE(data, 1)
		case extensionKeyShare: // groups and key lengths
			var shares cryptobyte.String
			data.ReadUint16LengthPrefixed(&shares)
			var out []byte
			for !shares.Empty() {
				var group uint16
				var key cryptobyte.String
				shares.ReadUint16(&group)
				shares.ReadUint16LengthPrefixed(&key)
				if !isGREASE(group) {
					out = append(out, byte(group>>8), byte(group), byte(len(key)>>8), byte(len(key)))
				}
			}
			h.extensions[ext] = out
		case extensionEncryptedClientHello: // suite and payload length
			var outer uint8
			var kdf, aead uint16
			var configID uint8
			var enc, payload cryptobyte.String
			if !data.ReadUint8(&outer) || !data.ReadUint16(&kdf) || !data.ReadUint16(&aead) ||
				!data.ReadUint8(&configID) || !data.ReadUint16LengthPrefixed(&enc) ||
				!data.ReadUint16LengthPrefixed(&payload) {
				t.Fatal("bad GREASE ECH")
			}
			h.extensions[ext] = []byte{outer, byte(kdf), byte(aead), byte(len(enc))}
			h.echPayload = len(payload)
		default:
			h.extensions[ext] = []byte(data)
		}
	}
	return h
}

// captureClientHello handshakes with a local server and returns the first
// TLS record the client sent.
func captureClientHello(t *testing.T, config *Config) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var record bytes.Buffer
		header := make([]byte, 5)
		if _, err := conn.Read(header); err == nil {
			n := int(header[3])<<8 | int(header[4])
			rest := make([]byte, n)
			if _, err := io.ReadFull(conn, rest); err == nil {
				record.Write(header)
				record.Write(rest)
			}
		}
		got <- record.Bytes()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	go Client(conn, config).Handshake() // the server never answers
	return <-got
}

// testCertificate returns a self-signed certificate for a local server.
func testCertificate(t *testing.T) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestChromeClientHello compares our ClientHello with a real Chrome 155's
// (testdata/chrome155_clienthello.md), which Chrome 156 also sends.
func TestChromeClientHello(t *testing.T) {
	data, err := os.ReadFile("testdata/chrome155_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	want := parseChromeHello(t, capture)

	record := captureClientHello(t, &Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}})
	got := parseChromeHello(t, record)

	if !slices.Equal(got.ciphers, want.ciphers) {
		t.Errorf("cipher suites: got %04x, want %04x", got.ciphers, want.ciphers)
	}
	for ext, wantData := range want.extensions {
		gotData, ok := got.extensions[ext]
		if !ok {
			t.Errorf("missing extension %d", ext)
		} else if !bytes.Equal(gotData, wantData) {
			t.Errorf("extension %d: got %x, want %x", ext, gotData, wantData)
		}
	}
	for ext := range got.extensions {
		if _, ok := want.extensions[ext]; !ok {
			t.Errorf("extra extension %d", ext)
		}
	}
	if !slices.Contains([]int{144, 176, 208, 240}, got.echPayload) {
		t.Errorf("GREASE ECH payload of %d bytes, not one of BoringSSL's", got.echPayload)
	}
}

// The transcript and the wire must see the same ClientHello, though Go
// marshals it more than once.
func TestTransformClientHelloIsDeterministic(t *testing.T) {
	hello := &clientHelloMsg{
		vers:                         VersionTLS12,
		random:                       bytes.Repeat([]byte{7}, 32),
		sessionId:                    bytes.Repeat([]byte{9}, 32),
		cipherSuites:                 chromeCipherSuites,
		compressionMethods:           []uint8{compressionNone},
		serverName:                   "www.example.com",
		alpnProtocols:                []string{"h2", "http/1.1"},
		supportedVersions:            []uint16{VersionTLS13, VersionTLS12},
		supportedCurves:              []CurveID{X25519MLKEM768, X25519},
		supportedPoints:              []uint8{pointFormatUncompressed},
		supportedSignatureAlgorithms: chromeSignatureAlgorithms,
		keyShares:                    []keyShare{{group: X25519, data: bytes.Repeat([]byte{1}, 32)}},
		secureRenegotiationSupported: true,
	}
	a, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two marshals of the same ClientHello differ")
	}
}

// A handshake with a standard library server works, and gets compressed
// certificates right if the server sends them.
func TestHandshakeWithStdlibServer(t *testing.T) {
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{testCertificate(t)},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
	}()
	conn, err := Dial("tcp", ln.Addr().String(), &Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("got %q, %v", buf, err)
	}
	if st := conn.ConnectionState(); st.NegotiatedProtocol != "h2" || st.CurveID != X25519MLKEM768 {
		t.Errorf("negotiated %q with %v", st.NegotiatedProtocol, st.CurveID)
	}
}
