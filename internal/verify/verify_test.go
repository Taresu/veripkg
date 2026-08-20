package verify

import (
	"testing"

	"github.com/tsalada/veripkg/internal/sumsfile"
)

const (
	hashA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	hashB = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func TestPinnedHash(t *testing.T) {
	tests := []struct {
		name     string
		actual   string
		expected string
		want     Tier
	}{
		{"match", hashA, hashA, TierPinnedHash},
		{"match uppercase pin", hashA, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", TierPinnedHash},
		{"mismatch", hashA, hashB, TierUnverified},
		{"empty pin refuses", hashA, "", TierUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := PinnedHash("f", tt.actual, tt.expected)
			if r.Tier != tt.want {
				t.Fatalf("Tier = %v (%s), want %v — %s", r.Tier, r.Tier, tt.want, r.Reason)
			}
		})
	}
}

func TestSignedSums(t *testing.T) {
	sums := sumsfile.Sums{"file.deb": hashA}

	tests := []struct {
		name   string
		file   string
		actual string
		keyFpr string
		want   Tier
	}{
		{"signed match", "file.deb", hashA, "ABCD1234", TierSigned},
		{"no trusted key refuses", "file.deb", hashA, "", TierUnverified},
		{"whitespace key refuses", "file.deb", hashA, "   ", TierUnverified},
		{"name not in sums", "other.deb", hashA, "ABCD1234", TierUnverified},
		{"hash mismatch", "file.deb", hashB, "ABCD1234", TierUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := SignedSums("f", tt.file, tt.actual, sums, tt.keyFpr)
			if r.Tier != tt.want {
				t.Fatalf("Tier = %v (%s), want %v — %s", r.Tier, r.Tier, tt.want, r.Reason)
			}
			if tt.want == TierSigned && r.KeyFingerprint == "" {
				t.Error("expected key fingerprint recorded on signed result")
			}
		})
	}
}

func TestTierProperties(t *testing.T) {
	if !TierSigned.OK() || !TierPinnedHash.OK() {
		t.Error("verified tiers must report OK")
	}
	if TierUnverified.OK() {
		t.Error("unverified must not report OK")
	}
	if !(TierSigned > TierPinnedHash && TierPinnedHash > TierUnverified) {
		t.Error("tier ordering wrong")
	}
}
