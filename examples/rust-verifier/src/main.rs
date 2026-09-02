use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use oxdeai_rust_verifier::types::{AuthorizationV1, KeySet};
use oxdeai_rust_verifier::verify_authorization::verify_authorization;

/// Decides the trusted verification time given an optional raw VERIFY_NOW
/// value and the real wall-clock time. Pure: no env I/O, so the malformed
/// case is testable without mutating process-global env state.
///
/// verify_now absent -> real_now. verify_now a valid i64 -> that fixed
/// protocol-time value, so a bundled fixture can be verified deterministically
/// instead of drifting into AUTH_EXPIRED as real time passes. verify_now
/// present but not a valid i64 is a configuration error: fail closed rather
/// than silently falling back to real_now, which would mask the caller's
/// mistake as a still-passing verification.
fn resolve_now(verify_now: Option<&str>, real_now: i64) -> Result<i64, String> {
    match verify_now {
        None => Ok(real_now),
        Some(raw) => raw
            .parse::<i64>()
            .map_err(|_| format!("VERIFY_NOW is set but is not a valid integer: {raw:?}")),
    }
}

fn now_unix() -> Result<i64, String> {
    let real_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    match std::env::var("VERIFY_NOW") {
        Ok(raw) => resolve_now(Some(&raw), real_now),
        Err(std::env::VarError::NotPresent) => Ok(real_now),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("VERIFY_NOW is set but is not valid unicode".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_now;

    #[test]
    fn absent_uses_real_now() {
        assert_eq!(resolve_now(None, 42), Ok(42));
    }

    #[test]
    fn valid_i64_overrides_real_now() {
        assert_eq!(resolve_now(Some("1775656951"), 0), Ok(1775656951));
    }

    #[test]
    fn malformed_is_explicit_error() {
        let result = resolve_now(Some("not-a-number"), 0);
        assert!(result.is_err(), "expected an error, got {result:?}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cargo run -- <auth.json> <keyset.json> <expected_audience>");
        std::process::exit(2);
    }

    let auth_raw = match fs::read_to_string(&args[1]) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_MALFORMED: failed to read auth file)");
            std::process::exit(1);
        }
    };

    let keyset_raw = match fs::read_to_string(&args[2]) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_KEY_MALFORMED: failed to read keyset file)");
            std::process::exit(1);
        }
    };

    let auth: AuthorizationV1 = match serde_json::from_str(&auth_raw) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_MALFORMED: invalid auth json)");
            std::process::exit(1);
        }
    };

    let keyset: KeySet = match serde_json::from_str(&keyset_raw) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_KEY_MALFORMED: invalid keyset json)");
            std::process::exit(1);
        }
    };

    let now = match now_unix() {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("ERROR: {msg}");
            std::process::exit(2);
        }
    };

    let result = verify_authorization(&auth, &keyset, &args[3], now);

    if result.status == "ok" {
        println!("ALLOW");
        return;
    }

    if let Some(v) = result.violations.first() {
        eprintln!("DENY ({}: {})", v.code, v.message);
    } else {
        eprintln!("DENY (AUTH_VERIFICATION_ERROR: unknown)");
    }
    std::process::exit(1);
}
