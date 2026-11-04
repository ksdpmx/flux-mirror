// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"sigs.k8s.io/yaml"
)

// maxChartYAMLSize bounds how much of a Chart.yaml is read from a tarball.
const maxChartYAMLSize = 1 << 20

// ChartIdentity returns the name and version declared by the top-level
// <chart>/Chart.yaml of a chart .tgz. It reads only that entry from the tar
// stream, so it does not expand the rest of the chart.
func ChartIdentity(tgz []byte) (name, version string, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return "", "", fmt.Errorf("open chart archive: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", "", errors.New("chart archive has no top-level Chart.yaml")
		}
		if err != nil {
			return "", "", fmt.Errorf("read chart archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA is what old archives use.
			continue
		}
		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		// A chart lives in a single top-level directory; skip charts/<dep>/Chart.yaml.
		if strings.Count(clean, "/") != 1 || path.Base(clean) != "Chart.yaml" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxChartYAMLSize+1))
		if err != nil {
			return "", "", fmt.Errorf("read Chart.yaml: %w", err)
		}
		if len(data) > maxChartYAMLSize {
			return "", "", fmt.Errorf("size of Chart.yaml exceeds %d bytes", maxChartYAMLSize)
		}
		var meta struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := yaml.Unmarshal(data, &meta); err != nil {
			return "", "", fmt.Errorf("parse Chart.yaml: %w", err)
		}
		if meta.Name == "" || meta.Version == "" {
			return "", "", errors.New("no name or version in Chart.yaml")
		}
		return meta.Name, meta.Version, nil
	}
}
