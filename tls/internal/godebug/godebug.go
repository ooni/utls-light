// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug stands in for internal/godebug, which only the standard
// library can import. It reads the GODEBUG environment variable once, so
// that crypto/tls's settings (e.g. tlsmlkem=0) still work, and doesn't
// count non-default uses.
package godebug

import (
	"os"
	"strings"
	"sync"
)

// A Setting is a single setting in the GODEBUG environment variable.
type Setting struct {
	name string
}

// New returns a new Setting for the GODEBUG name, which may start with
// '#' as in internal/godebug.
func New(name string) *Setting {
	return &Setting{name: strings.TrimPrefix(name, "#")}
}

// Name returns the name of the setting.
func (s *Setting) Name() string {
	return s.name
}

// Value returns the setting's value in GODEBUG, or "" if it's unset.
func (s *Setting) Value() string {
	return settings()[s.name]
}

// IncNonDefault does nothing: there are no runtime/metrics to update.
func (s *Setting) IncNonDefault() {}

var settings = sync.OnceValue(func() map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
})
