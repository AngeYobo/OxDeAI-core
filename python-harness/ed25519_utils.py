#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Shared Ed25519 verification utilities for cross-language conformance harnesses.

Provides OpenSSL-backed Ed25519 verification via ctypes (no external Python packages).
Used by both verify_signed_krl_vectors.py and verify_profile_c_vectors.py.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import sys
from typing import Optional


# ── OpenSSL loading ───────────────────────────────────────────────────────────

def load_openssl() -> ctypes.CDLL:
    """Load libcrypto. Exits non-zero if not found — infrastructure failure."""
    candidates = [
        ctypes.util.find_library("crypto"),
        "libcrypto.so.3",
        "libcrypto.so.1.1",
        "libcrypto.dylib",
    ]
    for path in candidates:
        if path is None:
            continue
        try:
            lib = ctypes.CDLL(path)
            # Configure required function signatures.
            lib.EVP_PKEY_free.restype = None
            lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
            lib.EVP_MD_CTX_free.restype = None
            lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
            lib.EVP_PKEY_new_raw_public_key.argtypes = [
                ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ]
            lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
            lib.EVP_DigestVerifyInit.restype = ctypes.c_int
            lib.EVP_DigestVerifyInit.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_void_p,
            ]
            lib.EVP_DigestVerify.restype = ctypes.c_int
            lib.EVP_DigestVerify.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
            ]
            return lib
        except OSError:
            continue
    print(
        "FATAL: OpenSSL libcrypto not found. Required for Ed25519 signature verification. "
        "Tried: " + ", ".join(repr(c) for c in candidates),
        file=sys.stderr,
    )
    sys.exit(1)


# Load once at module level — failure is an infrastructure error.
OPENSSL: ctypes.CDLL = load_openssl()

# EVP_PKEY type ID for Ed25519 in OpenSSL.
EVP_PKEY_ED25519: int = 1087

# Fixed byte length of the SPKI DER prefix for Ed25519 (302a300506032b6570032100).
SPKI_PREFIX_LEN: int = 12


# ── Infrastructure errors ─────────────────────────────────────────────────────

class InfrastructureError(Exception):
    """Non-recoverable infrastructure failure (PEM parse, key creation, etc.)."""


# ── Key helpers ───────────────────────────────────────────────────────────────

def parse_ed25519_pem(pem_str: str) -> bytes:
    """Parse SPKI PEM-encoded Ed25519 public key to raw 32 bytes.

    Strips PEM armor, base64-decodes the DER body, and extracts the last
    32 bytes (the raw public key material after the 12-byte SPKI prefix).

    Raises InfrastructureError on malformed input.
    No vector tests malformed key material — any parse failure is a bug.
    """
    lines = [
        line.strip()
        for line in pem_str.strip().splitlines()
        if not line.strip().startswith("-----")
    ]
    try:
        der = base64.b64decode("".join(lines))
    except Exception as exc:
        raise InfrastructureError(
            f"Failed to base64-decode PEM body: {exc}"
        ) from exc

    expected_total = SPKI_PREFIX_LEN + 32
    if len(der) != expected_total:
        raise InfrastructureError(
            f"Unexpected DER key length: {len(der)} bytes (expected {expected_total})"
        )

    return der[SPKI_PREFIX_LEN:]


def ed25519_verify(raw_pub: bytes, message: bytes, sig_bytes: bytes) -> bool:
    """Verify an Ed25519 signature using the EVP path in libcrypto.

    Uses NULL digest (Ed25519 signs the exact message bytes without pre-hashing).
    Returns True on valid signature, False otherwise.
    """
    lib = OPENSSL
    pkey = lib.EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, None, raw_pub, len(raw_pub))
    if not pkey:
        return False

    ctx = lib.EVP_MD_CTX_new()
    if not ctx:
        lib.EVP_PKEY_free(pkey)
        return False

    try:
        if lib.EVP_DigestVerifyInit(ctx, None, None, None, pkey) != 1:
            return False
        return lib.EVP_DigestVerify(ctx, sig_bytes, len(sig_bytes), message, len(message)) == 1
    finally:
        lib.EVP_MD_CTX_free(ctx)
        lib.EVP_PKEY_free(pkey)


def decode_base64url(s: str) -> bytes:
    """Decode a base64url-encoded string (no padding required).

    Used for Encoding B AuthorizationV1 signature bytes (base64url, RFC 4648 §5).
    SignedKRLV1 uses standard base64; only Encoding B uses base64url.
    """
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)
