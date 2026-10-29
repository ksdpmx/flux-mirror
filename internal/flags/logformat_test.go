// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestLogFormat_Set(t *testing.T) {
	tests := []struct {
		name      string
		str       string
		expect    string
		expectErr bool
	}{
		{"text", "text", "text", false},
		{"json", "json", "json", false},
		{"unsupported", "yaml", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			var l LogFormat
			err := l.Set(tt.str)
			if tt.expectErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(l.String()).To(Equal(tt.expect))
		})
	}
}
