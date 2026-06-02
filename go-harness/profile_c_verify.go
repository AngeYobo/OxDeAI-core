// SPDX-License-Identifier: Apache-2.0
// Profile C state-hash semantics conformance vectors (modes 001–008).
// Modes 001–005: canonicalization-v1 + SHA-256 only.
// Modes 006–008: additionally require Encoding B AuthorizationV1 signature
// verification (alg='ed25519', expires_at, base64url signature, no domain prefix).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProfileCOutcome is the result of a Profile C state-hash comparison.
type ProfileCOutcome string

const (
	ProfileCOutcomeOk                ProfileCOutcome = "ok"
	ProfileCOutcomeStateHashMismatch ProfileCOutcome = "state-hash-mismatch"
	ProfileCOutcomeComputeError      ProfileCOutcome = "compute-error"
)

// ── Hash strategies ───────────────────────────────────────────────────────────

func computeCoreHash(state interface{}) (string, error) {
	canonical, err := canonicalize(state)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", h[:]), nil
}

func computeProviderHash(state interface{}) (string, error) {
	canonical, err := canonicalize(state)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte("PROVIDER:" + canonical))
	return fmt.Sprintf("%x", h[:]), nil
}

func computeThrowsHash(_ interface{}) (string, error) {
	return "", errors.New("hash backend unavailable")
}

func getProfileCHashFn(strategy string) func(interface{}) (string, error) {
	switch strategy {
	case "core":
		return computeCoreHash
	case "provider":
		return computeProviderHash
	case "throws":
		return computeThrowsHash
	default:
		return nil
	}
}

// ── Encoding B AuthorizationV1 verification ───────────────────────────────────

// buildEncodingBSigningPayload reconstructs the Encoding B signing payload
// from a committed auth artifact.
//
// The signing payload includes all auth fields EXCEPT signature.sig.
// signature becomes { alg, kid } with sig excluded.
// The preimage is canonicalJson(signingPayload) with NO domain prefix.
//
// This is the Sift-compatible Encoding B wire format - distinct from:
//   - Encoding A: uses "OXDEAI_AUTH_V1\n" domain prefix
//   - SignedKRLV1: uses "OXDEAI_KRL_V1\n" domain prefix
func buildEncodingBSigningPayload(auth map[string]interface{}) map[string]interface{} {
	sig, _ := auth["signature"].(map[string]interface{})
	payload := make(map[string]interface{})
	for k, v := range auth {
		if k == "signature" {
			// Include only alg and kid - sig is intentionally excluded.
			payload["signature"] = map[string]interface{}{
				"alg": sig["alg"],
				"kid": sig["kid"],
			}
		} else {
			payload[k] = v
		}
	}
	return payload
}

// verifyEncodingBAuth verifies an Encoding B AuthorizationV1 artifact.
//
// Preimage: canonicalJson(signingPayload) - NO domain prefix.
// Signature: base64url Ed25519 (RFC 4648 §5, no padding).
//
// Infrastructure failures (malformed PEM, invalid base64) call os.Exit(1).
// This function is only called for committed portable vectors; any failure
// is a harness implementation bug, not a test outcome.
func verifyEncodingBAuth(auth map[string]interface{}, pubKeyPem string, id string) bool {
	// Extract signature bytes (base64url).
	sig, _ := auth["signature"].(map[string]interface{})
	sigStr, _ := sig["sig"].(string)

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: failed to decode base64url signature: %v\n", id, err)
		os.Exit(1)
	}

	// Parse the Ed25519 public key from SPKI PEM.
	// Reuses parseEd25519PEM from signed_krl_verify.go (same package).
	pubKey, err := parseEd25519PEM(pubKeyPem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: failed to parse Ed25519 PEM key: %v\n", id, err)
		os.Exit(1)
	}

	// Reconstruct the signing payload and canonicalize.
	signingPayload := buildEncodingBSigningPayload(auth)
	canonical, err := canonicalize(signingPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: canonicalization failed: %v\n", id, err)
		os.Exit(1)
	}

	// Preimage: canonical JSON bytes with NO domain prefix.
	preimage := []byte(canonical)

	return ed25519.Verify(pubKey, preimage, sigBytes)
}

// ── Vector loading ────────────────────────────────────────────────────────────

type profileCVectorFile struct {
	Vectors []json.RawMessage `json:"vectors"`
}

func loadProfileCVectors() ([]map[string]interface{}, error) {
	dir := testVectorsDir()
	if dir == "" {
		return nil, fmt.Errorf("unable to resolve vectors directory")
	}
	path := filepath.Join(dir, "profile-c-state-verification.json")

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var raw interface{}
	dec := json.NewDecoder(f)
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	top, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vector file root is not an object")
	}
	vectorsRaw, ok := top["vectors"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("vectors field is not an array")
	}

	result := make([]map[string]interface{}, len(vectorsRaw))
	for i, v := range vectorsRaw {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("vector %d is not an object", i)
		}
		result[i] = m
	}
	return result, nil
}

// ── Outcome computation ───────────────────────────────────────────────────────

func computeProfileCOutcome(v map[string]interface{}) ProfileCOutcome {
	mode, _ := v["mode"].(string)

	// compute-throws: simulate computeStateHash failure directly.
	if mode == "compute-throws" {
		return ProfileCOutcomeComputeError
	}

	// Encoding B modes: verify Encoding B signature, then compare state hashes.
	if strings.HasPrefix(mode, "encoding-b-") {
		return computeEncodingBOutcome(v)
	}

	// Modes 001–005: pure state-hash comparison, no signature work.
	return computeStateHashOutcome(v)
}

// computeStateHashOutcome handles modes 001–005 (no signature).
func computeStateHashOutcome(v map[string]interface{}) ProfileCOutcome {
	hashStrategy, _ := v["hash_strategy"].(string)
	signingStrategy := hashStrategy
	if s, ok := v["signing_strategy"].(string); ok && s != "" {
		signingStrategy = s
	}
	verifyStrategy := hashStrategy
	if s, ok := v["verify_strategy"].(string); ok && s != "" {
		verifyStrategy = s
	}

	signingFn := getProfileCHashFn(signingStrategy)
	verifyFn := getProfileCHashFn(verifyStrategy)
	if signingFn == nil || verifyFn == nil {
		return ProfileCOutcomeComputeError
	}

	stateInput := v["state_input"]
	committedHash, err := signingFn(stateInput)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

	liveState := stateInput
	if ls, ok := v["live_state_input"]; ok && ls != nil {
		liveState = ls
	}

	liveHash, err := verifyFn(liveState)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

	if liveHash == committedHash {
		return ProfileCOutcomeOk
	}
	return ProfileCOutcomeStateHashMismatch
}

// computeEncodingBOutcome handles modes 006–008 (Encoding B).
//
// Step 1: Verify Encoding B signature (fatal on failure - harness bug).
// Step 2: Independently compute committedHash from state_input.
// Step 3: Cross-check committedHash against auth.state_hash (byte-equivalence proof).
// Step 4: Compute liveHash using verify strategy.
// Step 5: Compare liveHash vs committedHash.
func computeEncodingBOutcome(v map[string]interface{}) ProfileCOutcome {
	id, _ := v["id"].(string)
	auth, _ := v["auth"].(map[string]interface{})
	opts, _ := v["opts"].(map[string]interface{})
	trustedKey, _ := opts["trustedKey"].(map[string]interface{})
	pubKeyPem, _ := trustedKey["public_key"].(string)

	// Step 1: Verify Encoding B signature independently.
	// Preimage = canonicalJson(signingPayload), NO domain prefix.
	if !verifyEncodingBAuth(auth, pubKeyPem, id) {
		fmt.Fprintf(os.Stderr, "FATAL [%s]: Encoding B signature verification failed - harness bug (wrong preimage or key?)\n", id)
		os.Exit(1)
	}

	// Step 2: Independently compute committedHash from state_input.
	hashStrategy, _ := v["hash_strategy"].(string)
	signingStrategy := hashStrategy
	if s, ok := v["signing_strategy"].(string); ok && s != "" {
		signingStrategy = s
	}
	verifyStrategy := hashStrategy
	if s, ok := v["verify_strategy"].(string); ok && s != "" {
		verifyStrategy = s
	}

	signingFn := getProfileCHashFn(signingStrategy)
	verifyFn := getProfileCHashFn(verifyStrategy)
	if signingFn == nil || verifyFn == nil {
		return ProfileCOutcomeComputeError
	}

	stateInput := v["state_input"]
	committedHash, err := signingFn(stateInput)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

	// Step 3: Cross-check committedHash against committed auth.state_hash.
	// If they differ, the canonicalization or hash strategy in this harness is
	// wrong - this is a byte-equivalence failure, not a test outcome.
	authStateHash, _ := auth["state_hash"].(string)
	if committedHash != authStateHash {
		fmt.Fprintf(os.Stderr,
			"FATAL [%s]: independently-computed committedHash %s does not match committed auth.state_hash %s\n"+
				"  This indicates a canonicalization or hash-strategy bug in the Go harness.\n",
			id, committedHash, authStateHash)
		os.Exit(1)
	}

	// Step 4: Compute liveHash using verify strategy.
	liveState := stateInput
	if ls, ok := v["live_state_input"]; ok && ls != nil {
		liveState = ls
	}

	liveHash, err := verifyFn(liveState)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

	// Step 5: Compare liveHash vs committedHash.
	if liveHash == committedHash {
		return ProfileCOutcomeOk
	}
	return ProfileCOutcomeStateHashMismatch
}

// ── Runner ────────────────────────────────────────────────────────────────────

func verifyProfileCVectors() (passed, failed int) {
	vectors, err := loadProfileCVectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Profile C: failed to load vectors: %v\n", err)
		os.Exit(1)
	}

	for _, v := range vectors {
		id, _ := v["id"].(string)
		expected, _ := v["expected"].(map[string]interface{})
		expectedOutcome, _ := expected["outcome"].(string)

		got := computeProfileCOutcome(v)

		if string(got) != expectedOutcome {
			failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: outcome mismatch\n", id)
			fmt.Fprintf(os.Stderr, "  expected: %s\n", expectedOutcome)
			fmt.Fprintf(os.Stderr, "  actual:   %s\n", string(got))
			continue
		}
		fmt.Printf("PASS %s\n", id)
		passed++
	}
	return
}
