// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts

import (
	"context"
	"fmt"
	"strings"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta1"
	"github.com/fluxcd/flux-mirror/internal/helmrepo"
	"github.com/fluxcd/flux-mirror/internal/registryauth"
	"github.com/fluxcd/flux-mirror/internal/sync"
)

// prepareHelmRepo builds the Helm repository client and checks that the source
// is an OCI Helm chart by inspecting the first selected tag. Failing here, in
// Plan, surfaces a misconfigured entry (an image with destinationType
// "artifactory") before any work and also under --dry-run.
func (m *mirror) prepareHelmRepo(ctx context.Context, tags []string) error {
	pusher, err := m.newPusher()
	if err != nil {
		return err
	}
	m.pusher = pusher
	if len(tags) == 0 {
		return nil
	}
	ref := m.entry.Source + ":" + tags[0]
	isChart, err := m.client.IsHelmChart(ctx, ref)
	if err != nil {
		return err
	}
	if !isChart {
		return fmt.Errorf("source %s is not an OCI Helm chart (or does not exist); destinationType %q only supports Helm charts",
			ref, apiv1.DestinationTypeArtifactory)
	}
	return nil
}

func (m *mirror) newPusher() (*helmrepo.Pusher, error) {
	u, err := helmrepo.NormalizeDestination(m.entry.Destination)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	opts := []helmrepo.PusherOption{helmrepo.WithTransport(m.opts.Transport)}
	for _, h := range m.opts.Hosts {
		if !strings.EqualFold(h.Host, u.Host) {
			continue
		}
		if h.Provider != "" {
			return nil, fmt.Errorf("host %q uses cloud provider %q, which is not supported for destinationType %q",
				h.Host, h.Provider, apiv1.DestinationTypeArtifactory)
		}
		// A credential without a username is a bearer token stamped by the
		// shared transport; only username credentials need Basic auth here.
		if registryauth.HasCredential(h) && h.Username != "" {
			opts = append(opts, helmrepo.WithBasicAuth(func(ctx context.Context) (string, string, error) {
				a, err := registryauth.ResolveHostAuth(ctx, h)
				return a.Username, a.Password, err
			}))
		}
		break
	}
	return helmrepo.NewPusher(m.entry.Destination, m.opts.Insecure, opts...)
}

// runChartTag mirrors one OCI Helm chart tag to the Helm repository. A failure
// (including a chart/tag version mismatch) fails only this tag. Idempotent —
// safe to retry under the runner's per-tag budget.
func (m *mirror) runChartTag(ctx context.Context, j tagJob) (res sync.JobResult, err error) {
	start := time.Now()
	var target string
	// Every log line carries the same identifying fields so the stream can be
	// filtered by source, tag, or destination in both text and JSON formats.
	base := func() []any {
		return []any{"source", m.entry.Source, "tag", j.tag, "destination", target}
	}
	defer func() {
		elapsed := time.Since(start).Round(time.Millisecond)
		if err != nil {
			m.opts.Logger.Error("chart failed", append(base(),
				"event", "chart.failed", "error", err.Error(), "elapsed", elapsed)...)
			return
		}
		m.opts.Logger.Info("chart done", append(base(),
			"event", "chart.done", "status", string(res.Status), "digest", res.Digest, "elapsed", elapsed)...)
	}()

	// Pin to the digest confirmed by verification so the bytes uploaded are the
	// bytes whose signature was checked.
	ref := j.src
	if j.srcDigest != "" {
		ref = m.entry.Source + "@" + j.srcDigest
	}
	chart, err := m.client.OpenHelmChart(ctx, ref)
	if err != nil {
		return sync.JobResult{}, err
	}
	res = sync.JobResult{Digest: chart.LayerDigest}

	if want := strings.ReplaceAll(j.tag, "_", "+"); chart.Version != want {
		return res, fmt.Errorf("chart version %q in %s does not match tag %q", chart.Version, j.src, j.tag)
	}
	target, err = m.pusher.ChartURL(chart.Name, chart.Version)
	if err != nil {
		return res, err
	}
	m.opts.Logger.Info("mirroring chart", append(base(), "event", "chart.start")...)

	dstDigest, err := m.pusher.Stat(ctx, chart.Name, chart.Version)
	if err != nil {
		return res, err
	}

	switch {
	case dstDigest == "":
		res.Status = apiv1.StatusCopied
		if m.opts.DryRun {
			res.Status = apiv1.StatusWouldCopy
		}
	case dstDigest == chart.LayerDigest:
		m.opts.Logger.Info("skipping chart", append(base(),
			"event", "chart.skip", "digest", chart.LayerDigest,
			"reason", "destination chart is up to date")...)
		res.Status = apiv1.StatusSkipped
		res.Reason = apiv1.ReasonUpToDate
		return res, nil
	case !j.overwrite:
		m.opts.Logger.Warn("destination chart drifted from source; skipping (overwrite=false)", append(base(),
			"event", "chart.drift", "digest", chart.LayerDigest, "dst_digest", dstDigest,
			"reason", "destination chart differs from source and overwrite is false")...)
		res.Status = apiv1.StatusDrifted
		return res, nil
	default:
		res.Status = apiv1.StatusOverwritten
		if m.opts.DryRun {
			res.Status = apiv1.StatusWouldOverwrite
		}
	}
	if m.opts.DryRun {
		return res, nil
	}

	body, err := chart.Open()
	if err != nil {
		return res, fmt.Errorf("open chart layer of %s: %w", j.src, err)
	}
	defer body.Close()
	if err := m.pusher.Put(ctx, chart.Name, chart.Version, body, chart.Size, chart.LayerDigest); err != nil {
		return res, err
	}
	return res, nil
}
