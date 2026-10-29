// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"fmt"
	"slices"
	"strings"
)

var supportedLogFormats = []string{"text", "json"}

// LogFormat is the format of the --verbose log stream.
type LogFormat string

func (l *LogFormat) String() string {
	return string(*l)
}

func (l *LogFormat) Set(str string) error {
	if strings.TrimSpace(str) == "" {
		return fmt.Errorf("no log format given, must be one of: %s",
			strings.Join(supportedLogFormats, ", "))
	}
	if !slices.Contains(supportedLogFormats, str) {
		return fmt.Errorf("unsupported log format '%s', must be one of: %s",
			str, strings.Join(supportedLogFormats, ", "))
	}
	*l = LogFormat(str)
	return nil
}

func (l *LogFormat) Type() string {
	return strings.Join(supportedLogFormats, "|")
}

func (l *LogFormat) Description() string {
	return fmt.Sprintf("format of the --verbose log stream on stderr, can be one of: %s",
		strings.Join(supportedLogFormats, ", "))
}
