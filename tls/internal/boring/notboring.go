// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boring stands in for crypto/internal/boring: utls-light never
// uses BoringCrypto. From refraction-networking/utls.
package boring

import (
	"crypto/cipher"
	"errors"
)

const Enabled bool = false

func NewGCMTLS(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func NewGCMTLS13(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func Unreachable() {
	// do nothing
}
