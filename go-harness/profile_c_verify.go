// SPDX-License-Identifier: Apache-2.0
// Profile C state-hash semantics conformance vectors (modes 001–005).
// Modes 006–008 (Encoding B) are TypeScript-only and are not implemented here.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// The "throws" strategy always errors; no state hash is computed.
	if mode == "compute-throws" {
		return ProfileCOutcomeComputeError
	}

	// Determine signing and verify strategies.
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

	// Compute committed hash from state_input.
	stateInput := v["state_input"]
	committedHash, err := signingFn(stateInput)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

	// Live state defaults to state_input when live_state_input is absent.
	liveState := stateInput
	if ls, ok := v["live_state_input"]; ok && ls != nil {
		liveState = ls
	}

	// Compute live hash (verify strategy).
	liveHash, err := verifyFn(liveState)
	if err != nil {
		return ProfileCOutcomeComputeError
	}

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
