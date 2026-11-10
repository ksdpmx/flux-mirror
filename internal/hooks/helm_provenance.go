// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"helm.sh/helm/v4/pkg/provenance"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/helmrepo"
)

// HelmProvenanceBuilder creates a hook that verifies a chart archive against
// its Helm PGP-signed .prov sidecar.
func HelmProvenanceBuilder() Builder {
	return func(config apiv1.HookStep) (Step, error) {
		if config.Helm == nil {
			return nil, fmt.Errorf("helm provenance configuration is required")
		}
		keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(config.Helm.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse Helm provenance public key: %w", err)
		}
		if len(keyring) == 0 {
			return nil, fmt.Errorf("helm provenance public keyring is empty")
		}
		return helmProvenanceStep{
			signatory: &provenance.Signatory{KeyRing: keyring},
		}, nil
	}
}

type helmProvenanceStep struct {
	signatory *provenance.Signatory
}

func (s helmProvenanceStep) Units(_ context.Context, input Input) ([]Unit, error) {
	if input.HelmChart == nil {
		return nil, fmt.Errorf("helm provenance hook requires chart package data")
	}
	chart := input.HelmChart
	if chart.FetchProvenance == nil {
		return nil, fmt.Errorf("helm provenance hook requires a provenance fetcher")
	}
	return []Unit{{Run: func(ctx context.Context) (Outcome, error) {
		prov, filename, err := chart.FetchProvenance(ctx)
		if err != nil {
			if errors.Is(err, helmrepo.ErrProvenanceNotFound) {
				return Outcome{
					Verdict: apiv1.StepVerdictDeny,
					Reason:  "helm provenance file is missing",
				}, nil
			}
			return Outcome{}, err
		}
		if len(prov) == 0 {
			return Outcome{
				Verdict: apiv1.StepVerdictDeny,
				Reason:  "helm provenance file is empty",
			}, nil
		}
		if len(chart.Archive) == 0 || filename == "" {
			return Outcome{}, fmt.Errorf("helm provenance hook received incomplete chart package data")
		}
		if _, err := s.signatory.Verify(chart.Archive, prov, filename); err != nil {
			return Outcome{
				Verdict: apiv1.StepVerdictDeny,
				Reason:  fmt.Sprintf("helm provenance verification failed: %v", err),
			}, nil
		}
		return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
	}}}, nil
}
