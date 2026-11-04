// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

// Package charts implements sync.EntryMirror for ChartEntry config entries.
// It downloads chart .tgz bytes from the source (HTTP/S or OCI), then publishes
// them to the destination: as a deterministic Helm-OCI artifact
// (destinationType "oci") or as a .tgz uploaded to a JFrog Artifactory Helm
// repository (destinationType "artifactory").
//
// "Deterministic" matters for drift detection: the destination chart-layer
// digest equals sha256(srcChartTGZ), so a re-run with no changes is a clean
// no-op rather than a perpetual "different" state. See oci.HelmChartLayerDigest
// for the why.
package charts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/helmrepo"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/selector"
	"github.com/fluxcd/flux-mirror/internal/sync"
)

// Options configures the chart mirror across all entries. Mirrors the shape
// of internal/artifacts.Options for symmetry between the two halves.
type Options struct {
	// Overwrite forces overwrite=true on every entry, regardless of the
	// per-entry config. This is the global --overwrite flag.
	Overwrite bool
	// DryRun skips the actual push and reports would-* outcomes instead.
	DryRun bool
	// Verbose toggles selector debug output (logs versions excluded by
	// the semver constraint with reasons).
	Verbose bool
	// Logger is used for warnings and per-version progress lines.
	Logger *slog.Logger

	// Hosts, Transport and Insecure configure the HTTP client used for
	// destinationType "artifactory" entries: Hosts are the destination-side
	// hosts and supply Basic credentials, Transport is the shared transport that
	// stamps bearer credentials, and Insecure allows a plaintext http://
	// destination.
	Hosts     []apiv1.RegistryHost
	Transport http.RoundTripper
	Insecure  bool
}

// New builds an EntryMirror for the given chart entry. The source and the
// destination are created in Plan, so a bad URL or a plaintext http:// source
// without --insecure fails only this entry instead of aborting the whole sync.
func New(client *oci.Client, entry apiv1.ChartEntry, opts Options) (sync.EntryMirror, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &mirror{client: client, entry: entry, opts: opts}, nil
}

type mirror struct {
	client *oci.Client
	entry  apiv1.ChartEntry
	opts   Options
	source helmrepo.Source // set by Plan
	sink   sink            // set by Plan
}

// newSink builds the destination for the entry. It runs in Plan, not New, so a
// bad destination or an unsupported host fails only this entry (also with
// --dry-run) instead of aborting the whole sync.
func (m *mirror) newSink() (sink, error) {
	switch m.entry.EffectiveDestinationType() {
	case apiv1.DestinationTypeArtifactory:
		p, err := helmrepo.NewPusherForHosts(m.entry.Destination, m.opts.Insecure, m.opts.Transport, m.opts.Hosts)
		if err != nil {
			return nil, err
		}
		return &artifactorySink{pusher: p, name: m.entry.Name}, nil
	default:
		return newOCISink(m.client, m.entry.Destination, m.entry.Name), nil
	}
}

// versionJob captures everything resolved at plan time for a single chart
// version, so the Job's Run closure stays small.
type versionJob struct {
	version   string
	dst       string // fully-qualified destination ref or URL
	overwrite bool
}

// Plan resolves matching chart versions and emits one Job per version.
// Plan.Source uses "<source>/<chartName>" so logs and report rows disambiguate
// when multiple charts share a source URL. Plan.Destination is the OCI repo the
// chart lands in (destination base + chart name), or the Helm repository
// directory for destinationType "artifactory".
func (m *mirror) Plan(ctx context.Context) (sync.Plan, error) {
	plan := sync.Plan{Source: m.planName(), Destination: m.entry.Destination}

	src, err := helmrepo.New(m.entry.Source, m.opts.Insecure)
	if err != nil {
		return plan, err
	}
	m.source = src

	sink, err := m.newSink()
	if err != nil {
		return plan, err
	}
	m.sink = sink
	plan.Destination = sink.destination()

	versions, err := m.source.ListVersions(ctx, m.entry.Name)
	if err != nil {
		return plan, err
	}

	// Versions feed the selector as opaque strings — same shape as artifact tags.
	sel := apiv1.Selector{
		Semver: m.entry.EffectiveVersion(),
		Limit:  new(m.entry.EffectiveLimit()),
	}
	res, err := selector.Select(versions, sel, selector.Options{Verbose: m.opts.Verbose})
	if err != nil {
		return plan, fmt.Errorf("select versions: %w", err)
	}
	for _, ex := range res.Excluded {
		m.opts.Logger.Debug("version excluded by selector",
			"chart", m.entry.Name, "version", ex.Tag, "reason", ex.Reason)
	}

	overwrite := m.entry.Overwrite || m.opts.Overwrite

	plan.Jobs = make([]sync.Job, 0, len(res.Tags))
	for _, version := range res.Tags {
		dst, err := sink.target(version)
		if err != nil {
			// A version that cannot be stored (for example an unsafe file name)
			// is a per-version failure, not an entry failure.
			plan.Jobs = append(plan.Jobs, sync.Job{ID: version, PlanError: err})
			continue
		}
		job := versionJob{version: version, dst: dst, overwrite: overwrite}
		plan.Jobs = append(plan.Jobs, sync.Job{
			ID:  version,
			Dst: job.dst,
			Run: func(jctx context.Context) (sync.JobResult, error) { return m.runVersion(jctx, job) },
		})
	}
	return plan, nil
}

// runVersion mirrors one chart version. Idempotent — safe to retry under
// the runner's per-tag budget.
func (m *mirror) runVersion(ctx context.Context, j versionJob) (sync.JobResult, error) {
	start := time.Now()
	chartRef := m.entry.Name + "@" + j.version
	m.opts.Logger.Info("mirroring chart", "chart", chartRef, "dst", j.dst)

	res, err := m.mirrorVersion(ctx, j)
	if err != nil {
		return res, err
	}
	m.opts.Logger.Info("chart done",
		"chart", chartRef,
		"dst", j.dst,
		"status", string(res.Status),
		"elapsed", time.Since(start).Round(time.Millisecond))
	return res, nil
}

func (m *mirror) mirrorVersion(ctx context.Context, j versionJob) (sync.JobResult, error) {
	// Download src .tgz once. Bytes are pushed verbatim as the chart layer,
	// so sha256(tgz) is also the chart-layer digest at the destination if
	// our push goes through.
	tgz, err := m.source.Download(ctx, m.entry.Name, j.version)
	if err != nil {
		return sync.JobResult{}, err
	}
	srcLayerDigest := digestSHA256(tgz)

	// Compare against what the destination already holds for this version. For
	// OCI that is the chart-layer digest (see ociSink.digest); for Artifactory it
	// is the stored file's SHA-256. Both equal sha256(tgz) when unchanged.
	dstLayerDigest, err := m.sink.digest(ctx, j.version)
	if err != nil {
		return sync.JobResult{Digest: srcLayerDigest}, err
	}

	switch dstLayerDigest {
	case "":
		if m.opts.DryRun {
			return sync.JobResult{Status: apiv1.StatusWouldCopy, Digest: srcLayerDigest}, nil
		}
		if err := m.sink.push(ctx, j.version, tgz, srcLayerDigest); err != nil {
			return sync.JobResult{Digest: srcLayerDigest}, err
		}
		return sync.JobResult{Status: apiv1.StatusCopied, Digest: srcLayerDigest}, nil
	case srcLayerDigest:
		return sync.JobResult{Status: apiv1.StatusSkipped, Digest: srcLayerDigest, Reason: apiv1.ReasonUpToDate}, nil
	default:
		if !j.overwrite {
			m.opts.Logger.Warn("destination chart drifted from source; skipping (overwrite=false)",
				"chart", m.entry.Name, "version", j.version,
				"src_digest", srcLayerDigest, "dst_digest", dstLayerDigest)
			return sync.JobResult{Status: apiv1.StatusDrifted, Digest: srcLayerDigest}, nil
		}
		if m.opts.DryRun {
			return sync.JobResult{Status: apiv1.StatusWouldOverwrite, Digest: srcLayerDigest}, nil
		}
		if err := m.sink.push(ctx, j.version, tgz, srcLayerDigest); err != nil {
			return sync.JobResult{Digest: srcLayerDigest}, err
		}
		return sync.JobResult{Status: apiv1.StatusOverwritten, Digest: srcLayerDigest}, nil
	}
}

// planName is "<source>/<chart name>" with the source scheme made explicit
// (https when omitted), so reports show the URL that is actually used.
func (m *mirror) planName() string {
	source := m.entry.Source
	if u, err := helmrepo.NormalizeSource(source); err == nil {
		source = u.String()
	}
	return strings.TrimRight(source, "/") + "/" + m.entry.Name
}

func digestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
