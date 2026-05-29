// SPDX-License-Identifier: Apache-2.0
// SignedKRLV1 cross-language conformance verifier.
// Reads docs/spec/test-vectors/signed-krl-v1.json and independently
// reconstructs each signing preimage, verifies Ed25519 signatures, and
// checks all 9 portable vectors against expected reason-code verdicts.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KrlReasonCode is the exact string code for a SignedKRLV1 violation.
// These must be the only locations in go-harness/ where the KRL reason code
// string literals appear.
type KrlReasonCode string

const (
	KrlMalformed          KrlReasonCode = "KRL_MALFORMED"
	KrlSigInvalid         KrlReasonCode = "KRL_SIG_INVALID"
	KrlExpired            KrlReasonCode = "KRL_EXPIRED"
	KrlUnsupportedAlg     KrlReasonCode = "KRL_UNSUPPORTED_ALG"
	KrlUnknownSigningKid  KrlReasonCode = "KRL_UNKNOWN_SIGNING_KID"
	KrlSigningKeyInactive KrlReasonCode = "KRL_SIGNING_KEY_INACTIVE"
	KrlVersionRegression  KrlReasonCode = "KRL_VERSION_REGRESSION"
)

// krlViolation mirrors the violation shape in the vector expected field.
type krlViolation struct {
	Code string `json:"code"`
}

// krlVerifyResult is the outcome of a single SignedKRLV1 verification.
type krlVerifyResult struct {
	Status     string
	Violations []krlViolation
}

// ── Key helpers ───────────────────────────────────────────────────────────────

// parseEd25519PEM parses an SPKI PEM-encoded Ed25519 public key.
// PEM parse failures are infrastructure errors — the caller must exit on error.
func parseEd25519PEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block (empty or malformed)")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 public key")
	}
	return edPub, nil
}

// findKrlKey returns the first key entry matching issuer, kid, and alg="Ed25519",
// or nil when no match is found.
func findKrlKey(trustedKeySets []interface{}, issuer, kid string) map[string]interface{} {
	for _, ksRaw := range trustedKeySets {
		ks, ok := ksRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if ks["issuer"] != issuer {
			continue
		}
		keys, _ := ks["keys"].([]interface{})
		for _, kRaw := range keys {
			k, ok := kRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if k["kid"] == kid && k["alg"] == "Ed25519" {
				return k
			}
		}
	}
	return nil
}

// keyIsActiveAt returns true when the key is valid at the given unix-second
// timestamp, following the same semantics as keyIsActiveAt in @oxdeai/core:
//
//	status == "revoked"                → false
//	not_before present && now < nb    → false
//	not_after  present && now > na    → false
//	otherwise                          → true
func keyIsActiveAt(key map[string]interface{}, nowSec int64) bool {
	if status, _ := key["status"].(string); status == "revoked" {
		return false
	}
	if nbRaw, ok := key["not_before"].(json.Number); ok {
		if nb, err := nbRaw.Int64(); err == nil && nowSec < nb {
			return false
		}
	}
	if naRaw, ok := key["not_after"].(json.Number); ok {
		if na, err := naRaw.Int64(); err == nil && nowSec > na {
			return false
		}
	}
	return true
}

// ── Signing payload ───────────────────────────────────────────────────────────

// buildKrlSigningPayload constructs the canonical signing payload from an
// envelope map. It includes all normative fields except signature.sig:
// version, issuer, krl_version, issued_at, not_after, revoked_kids,
// nonce (when present), signature.alg, signature.kid.
func buildKrlSigningPayload(envelope map[string]interface{}) (map[string]interface{}, error) {
	sig, ok := envelope["signature"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("signature is not an object")
	}

	payload := make(map[string]interface{})
	payload["version"] = envelope["version"]
	payload["issuer"] = envelope["issuer"]
	payload["krl_version"] = envelope["krl_version"]
	payload["issued_at"] = envelope["issued_at"]
	payload["not_after"] = envelope["not_after"]
	payload["revoked_kids"] = envelope["revoked_kids"]

	if nonce, ok := envelope["nonce"]; ok {
		payload["nonce"] = nonce
	}

	// signature.sig is intentionally excluded.
	payload["signature"] = map[string]interface{}{
		"alg": sig["alg"],
		"kid": sig["kid"],
	}
	return payload, nil
}

// ── Verifier ──────────────────────────────────────────────────────────────────

// verifySignedKrl verifies a SignedKRLV1 envelope following the check order
// specified in docs/spec/artifacts/signed-krl-v1.md and matching
// @oxdeai/core verifySignedKrl:
//
//  1. Structural / malformed    → KRL_MALFORMED (early return)
//  2. Unsupported algorithm     → KRL_UNSUPPORTED_ALG (early return)
//  3. Kid lookup                → KRL_UNKNOWN_SIGNING_KID
//  4. Key activity              → KRL_SIGNING_KEY_INACTIVE
//  5. Expiry                    → KRL_EXPIRED
//  6. Version regression        → KRL_VERSION_REGRESSION
//  7. Signature                 → KRL_SIG_INVALID
//
// Returns (result, infraErr). infraErr is non-nil only for infrastructure
// failures (e.g., PEM parse error on a key that was successfully looked up).
// The caller must exit non-zero on infrastructure failures.
func verifySignedKrl(
	envelope map[string]interface{},
	nowSec int64,
	trustedKeySets []interface{},
	prevVersions map[string]int64,
) (krlVerifyResult, error) {

	invalid := func(code KrlReasonCode) (krlVerifyResult, error) {
		return krlVerifyResult{
			Status:     "invalid",
			Violations: []krlViolation{{Code: string(code)}},
		}, nil
	}

	// ── 1. Structural checks (early return on any violation) ──────────────

	// version
	version, _ := envelope["version"].(string)
	if version != "SignedKRLV1" {
		return invalid(KrlMalformed)
	}

	// issuer
	issuer, ok := envelope["issuer"].(string)
	if !ok || issuer == "" {
		return invalid(KrlMalformed)
	}

	// krl_version
	krlVersionNum, ok := envelope["krl_version"].(json.Number)
	if !ok {
		return invalid(KrlMalformed)
	}
	krlVersion, err := krlVersionNum.Int64()
	if err != nil || krlVersion < 0 {
		return invalid(KrlMalformed)
	}

	// issued_at (required integer; informational only — not range-checked)
	if _, ok := envelope["issued_at"].(json.Number); !ok {
		return invalid(KrlMalformed)
	}

	// not_after
	notAfterNum, ok := envelope["not_after"].(json.Number)
	if !ok {
		return invalid(KrlMalformed)
	}
	notAfter, err := notAfterNum.Int64()
	if err != nil {
		return invalid(KrlMalformed)
	}

	// revoked_kids: must be array of strings with no duplicates
	kidsRaw, ok := envelope["revoked_kids"].([]interface{})
	if !ok {
		return invalid(KrlMalformed)
	}
	seenKids := make(map[string]struct{}, len(kidsRaw))
	for _, k := range kidsRaw {
		kStr, ok := k.(string)
		if !ok {
			return invalid(KrlMalformed)
		}
		if _, dup := seenKids[kStr]; dup {
			return invalid(KrlMalformed)
		}
		seenKids[kStr] = struct{}{}
	}

	// signature object
	sig, ok := envelope["signature"].(map[string]interface{})
	if !ok {
		return invalid(KrlMalformed)
	}

	// ── 2. Unsupported algorithm ──────────────────────────────────────────
	alg, _ := sig["alg"].(string)
	if alg == "" {
		return invalid(KrlMalformed)
	}
	if alg != "Ed25519" {
		return invalid(KrlUnsupportedAlg)
	}

	// signature.kid and signature.sig structural presence
	kid, _ := sig["kid"].(string)
	if kid == "" {
		return invalid(KrlMalformed)
	}
	sigStr, _ := sig["sig"].(string)
	if sigStr == "" {
		return invalid(KrlMalformed)
	}

	// ── 3. Kid lookup ─────────────────────────────────────────────────────
	keyEntry := findKrlKey(trustedKeySets, issuer, kid)
	if keyEntry == nil {
		return invalid(KrlUnknownSigningKid)
	}

	// ── 4. Key activity ───────────────────────────────────────────────────
	if !keyIsActiveAt(keyEntry, nowSec) {
		return invalid(KrlSigningKeyInactive)
	}

	// ── 5. Expiry (strict zero-tolerance: now >= not_after → KRL_EXPIRED) ─
	if nowSec >= notAfter {
		return invalid(KrlExpired)
	}

	// ── 6. Version regression ─────────────────────────────────────────────
	if prevVersions != nil {
		if prev, ok := prevVersions[issuer]; ok && krlVersion < prev {
			return invalid(KrlVersionRegression)
		}
	}

	// ── 7. Signature verification ─────────────────────────────────────────

	// PEM parse failure is an infrastructure error, not a test outcome.
	pubKeyPEM, _ := keyEntry["public_key"].(string)
	pubKey, err := parseEd25519PEM(pubKeyPEM)
	if err != nil {
		return krlVerifyResult{}, fmt.Errorf("KRL signing key PEM parse failure: %w", err)
	}

	// Reconstruct the canonical signing payload independently.
	signingPayload, err := buildKrlSigningPayload(envelope)
	if err != nil {
		return krlVerifyResult{}, fmt.Errorf("failed to build signing payload: %w", err)
	}

	canonical, err := canonicalize(signingPayload)
	if err != nil {
		return krlVerifyResult{}, fmt.Errorf("canonicalization failed: %w", err)
	}

	// Domain-prefixed preimage: "OXDEAI_KRL_V1\n" + canonicalJson(signingPayload)
	preimage := []byte("OXDEAI_KRL_V1\n" + canonical)

	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		// Malformed base64 is a signature format problem.
		return invalid(KrlSigInvalid)
	}

	if !ed25519.Verify(pubKey, preimage, sigBytes) {
		return invalid(KrlSigInvalid)
	}

	return krlVerifyResult{Status: "ok", Violations: []krlViolation{}}, nil
}

// ── Vector loading ────────────────────────────────────────────────────────────

func loadSignedKrlVectors() ([]map[string]interface{}, error) {
	dir := testVectorsDir()
	if dir == "" {
		return nil, fmt.Errorf("unable to resolve vectors directory")
	}
	path := filepath.Join(dir, "signed-krl-v1.json")

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

// ── Runner ────────────────────────────────────────────────────────────────────

func verifySignedKrlVectors() (passed, failed int) {
	vectors, err := loadSignedKrlVectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SignedKRL: failed to load vectors: %v\n", err)
		os.Exit(1)
	}

	for _, v := range vectors {
		id, _ := v["id"].(string)
		input, _ := v["input"].(map[string]interface{})
		expectedMap, _ := v["expected"].(map[string]interface{})

		envelope, _ := input["envelope"].(map[string]interface{})
		opts, _ := input["opts"].(map[string]interface{})

		// Extract opts.now
		nowNum, _ := opts["now"].(json.Number)
		nowSec, _ := nowNum.Int64()

		// Extract opts.trustedKeySets
		trustedKeySets, _ := opts["trustedKeySets"].([]interface{})

		// Extract opts.previousKrlVersionByIssuer (optional)
		var prevVersions map[string]int64
		if pRaw, ok := opts["previousKrlVersionByIssuer"].(map[string]interface{}); ok {
			prevVersions = make(map[string]int64, len(pRaw))
			for issuer, valRaw := range pRaw {
				if num, ok := valRaw.(json.Number); ok {
					if v, err := num.Int64(); err == nil {
						prevVersions[issuer] = v
					}
				}
			}
		}

		result, infraErr := verifySignedKrl(envelope, nowSec, trustedKeySets, prevVersions)
		if infraErr != nil {
			fmt.Fprintf(os.Stderr, "FATAL [%s]: infrastructure error: %v\n", id, infraErr)
			os.Exit(1)
		}

		// Compare status
		expectedStatus, _ := expectedMap["status"].(string)
		if result.Status != expectedStatus {
			failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: status mismatch\n", id)
			fmt.Fprintf(os.Stderr, "  expected: %s\n", expectedStatus)
			fmt.Fprintf(os.Stderr, "  actual:   %s\n", result.Status)
			continue
		}

		// Compare violations
		expectedViolsRaw, _ := expectedMap["violations"].([]interface{})
		if len(result.Violations) != len(expectedViolsRaw) {
			failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: violations count mismatch (expected %d, got %d)\n",
				id, len(expectedViolsRaw), len(result.Violations))
			continue
		}

		mismatch := false
		for i, ev := range expectedViolsRaw {
			evMap, _ := ev.(map[string]interface{})
			expectedCode, _ := evMap["code"].(string)
			if i >= len(result.Violations) || result.Violations[i].Code != expectedCode {
				mismatch = true
				fmt.Fprintf(os.Stderr, "FAIL %s: violation[%d] code mismatch\n", id, i)
				fmt.Fprintf(os.Stderr, "  expected: %s\n", expectedCode)
				if i < len(result.Violations) {
					fmt.Fprintf(os.Stderr, "  actual:   %s\n", result.Violations[i].Code)
				} else {
					fmt.Fprintf(os.Stderr, "  actual:   (missing)\n")
				}
				break
			}
		}
		if mismatch {
			failed++
			continue
		}

		fmt.Printf("PASS %s\n", id)
		passed++
	}
	return
}
