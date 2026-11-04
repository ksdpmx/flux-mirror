// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package charts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"helm.sh/helm/v4/pkg/chart/v2/loader"

	"github.com/fluxcd/flux-mirror/internal/helmrepo"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

// sink is where chart versions are published and read back for drift
// detection. The mirror's plan, drift, and outcome logic is the same for every
// kind of destination.
type sink interface {
	// destination is the Plan.Destination shown in logs and reports.
	destination() string
	// target is the destination reference or URL of version (Job.Dst).
	target(version string) (string, error)
	// digest returns the "sha256:<hex>" of the chart currently stored for
	// version, or "" when none exists.
	digest(ctx context.Context, version string) (string, error)
	// push publishes tgz, whose "sha256:<hex>" is tgzDigest, as version.
	push(ctx context.Context, version string, tgz []byte, tgzDigest string) error
}

// ociSink publishes charts as deterministic Helm-OCI artifacts under
// <destination>/<chart name>.
type ociSink struct {
	client *oci.Client
	repo   string // destination base plus chart name, without oci://
}

func newOCISink(client *oci.Client, destination, name string) *ociSink {
	base := strings.TrimPrefix(strings.TrimSpace(destination), "oci://")
	return &ociSink{client: client, repo: strings.TrimRight(base, "/") + "/" + name}
}

func (s *ociSink) destination() string { return s.repo }

func (s *ociSink) target(version string) (string, error) {
	return s.repo + ":" + helmrepo.VersionToTag(version), nil
}

// digest compares chart-layer digests, not manifest digests: manifest digests
// are non-deterministic for charts pushed by helm.sh/helm/v4/pkg/registry.Client.Push
// (timestamp annotation), but layer digests are content-addressed and stable.
func (s *ociSink) digest(ctx context.Context, version string) (string, error) {
	dst, _ := s.target(version)
	return s.client.HelmChartLayerDigest(ctx, dst)
}

// push extracts chart metadata from the .tgz to build the OCI config blob,
// then uploads the deterministic Helm-OCI artifact.
func (s *ociSink) push(ctx context.Context, version string, tgz []byte, _ string) error {
	chrt, err := loader.LoadArchive(bytes.NewReader(tgz))
	if err != nil {
		return fmt.Errorf("load chart archive: %w", err)
	}
	cfgJSON, err := json.Marshal(chrt.Metadata)
	if err != nil {
		return fmt.Errorf("marshal chart metadata: %w", err)
	}
	dst, _ := s.target(version)
	if _, err := s.client.PushHelmChart(ctx, dst, cfgJSON, tgz); err != nil {
		return err
	}
	return nil
}

// artifactorySink uploads the chart .tgz to a JFrog Artifactory Helm repository
// directory as <name>-<version>.tgz.
type artifactorySink struct {
	pusher *helmrepo.Pusher
	name   string
}

func (s *artifactorySink) destination() string { return s.pusher.Dir() }

func (s *artifactorySink) target(version string) (string, error) {
	return s.pusher.ChartURL(s.name, version)
}

func (s *artifactorySink) digest(ctx context.Context, version string) (string, error) {
	return s.pusher.Stat(ctx, s.name, version)
}

// push refuses a tarball whose Chart.yaml disagrees with the file name it would
// be stored under, so a mislabeled upstream archive fails only that version.
func (s *artifactorySink) push(ctx context.Context, version string, tgz []byte, tgzDigest string) error {
	name, ver, err := helmrepo.ChartIdentity(tgz)
	if err != nil {
		return fmt.Errorf("read chart metadata: %w", err)
	}
	if name != s.name || ver != version {
		return fmt.Errorf("chart archive declares %s@%s, expected %s@%s", name, ver, s.name, version)
	}
	return s.pusher.Put(ctx, s.name, version, bytes.NewReader(tgz), int64(len(tgz)), tgzDigest)
}
