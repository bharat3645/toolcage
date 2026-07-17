use std::path::PathBuf;

use serde_json::{json, Value};
use toolcage::audit::{fields, rfc3339_utc, sha256_hex, Auditor};

// ---------------------------------------------------------------------------
// SHA-256: FIPS 180-4 test vectors
// ---------------------------------------------------------------------------

#[test]
fn sha256_empty() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_abc() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_two_block_message() {
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_million_a() {
    let data = vec![b'a'; 1_000_000];
    assert_eq!(
        sha256_hex(&data),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha256_length_boundaries() {
    // 55/56/64 bytes cross the padding boundaries; just assert shape + stability.
    for n in [55usize, 56, 63, 64, 65] {
        let h = sha256_hex(&vec![0x41u8; n]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, sha256_hex(&vec![0x41u8; n]));
    }
}

// ---------------------------------------------------------------------------
// RFC 3339 timestamps (vectors cross-checked against Python datetime)
// ---------------------------------------------------------------------------

#[test]
fn rfc3339_epoch() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
}

#[test]
fn rfc3339_billionth_second() {
    assert_eq!(rfc3339_utc(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
}

#[test]
fn rfc3339_leap_day() {
    assert_eq!(rfc3339_utc(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
    assert_eq!(rfc3339_utc(1_709_210_096_789), "2024-02-29T12:34:56.789Z");
}

#[test]
fn rfc3339_century_boundary_and_millis() {
    assert_eq!(rfc3339_utc(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    assert_eq!(rfc3339_utc(1_752_796_800_123), "2025-07-18T00:00:00.123Z");
}

// ---------------------------------------------------------------------------
// Auditor behavior
// ---------------------------------------------------------------------------

#[test]
fn memory_sink_writes_jsonl_with_ts_and_event() {
    let a = Auditor::to_memory();
    a.log("session_start", fields(json!({ "k": 1 })));
    a.log("call", fields(json!({ "tool": "echo" })));
    let text = a.memory_contents().expect("memory sink");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("each audit line is JSON");
        assert!(v.get("ts").and_then(Value::as_str).is_some());
        assert!(v.get("event").and_then(Value::as_str).is_some());
    }
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["event"], "session_start");
    assert_eq!(first["k"], 1);
    assert_eq!(a.dropped(), 0);
}

#[test]
fn file_sink_appends_and_is_0600_on_unix() {
    let path = temp_path("toolcage-audit-test");
    let a = Auditor::to_file(&path).expect("open audit file");
    a.log("one", fields(json!({})));
    a.log("two", fields(json!({ "n": 2 })));
    drop(a);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "audit file must be 0600");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
#[should_panic]
fn fields_requires_object() {
    let _ = fields(json!([1, 2, 3]));
}

fn temp_path(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{}-{}-{}.jsonl", prefix, std::process::id(), nanos))
}
