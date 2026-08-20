package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Taresu/veripkg/internal/verify"
)

// resultJSON is the stable machine-readable shape of a verification result.
type resultJSON struct {
	Tier           string `json:"tier"`
	OK             bool   `json:"ok"`
	File           string `json:"file"`
	ActualHash     string `json:"actual_hash,omitempty"`
	ExpectedHash   string `json:"expected_hash,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	Reason         string `json:"reason"`
}

// report prints a result and returns the process exit code implied by its tier.
func report(w io.Writer, r verify.Result, asJSON bool) int {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resultJSON{
			Tier:           r.Tier.String(),
			OK:             r.Tier.OK(),
			File:           r.File,
			ActualHash:     r.ActualHash,
			ExpectedHash:   r.ExpectedHash,
			KeyFingerprint: r.KeyFingerprint,
			Reason:         r.Reason,
		})
	} else {
		mark := "✗"
		if r.Tier.OK() {
			mark = "✓"
		}
		fmt.Fprintf(w, "%s %s  %s\n", mark, r.Tier, r.File)
		if r.Reason != "" {
			fmt.Fprintf(w, "    %s\n", r.Reason)
		}
		if r.KeyFingerprint != "" {
			fmt.Fprintf(w, "    key: %s\n", r.KeyFingerprint)
		}
	}
	if r.Tier.OK() {
		return exitVerified
	}
	return exitRefused
}
