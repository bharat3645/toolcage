//! JSONL audit trail.
//!
//! Privacy invariant (same discipline as mcp-gateway-lite): tool call
//! arguments, results, and env values are NEVER written to the audit log.
//! Only names, byte counts, hashes, decisions, outcomes, and timings appear.
//! Hashes give correlation power without content.
//!
//! Sink failures never break a call: failed writes are counted and dropped.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

enum Sink {
    File(std::fs::File),
    Stderr,
    Memory(Vec<u8>),
}

pub struct Auditor {
    sink: Mutex<Sink>,
    dropped: AtomicU64,
}

impl Auditor {
    /// Append to a JSONL file, created 0600 on unix.
    pub fn to_file(path: &Path) -> Result<Auditor> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(path)
            .with_context(|| format!("failed to open audit log {}", path.display()))?;
        Ok(Auditor {
            sink: Mutex::new(Sink::File(file)),
            dropped: AtomicU64::new(0),
        })
    }

    /// Audit to stderr (stderr is a free channel for stdio MCP servers).
    pub fn to_stderr() -> Auditor {
        Auditor {
            sink: Mutex::new(Sink::Stderr),
            dropped: AtomicU64::new(0),
        }
    }

    /// In-memory sink for tests.
    pub fn to_memory() -> Auditor {
        Auditor {
            sink: Mutex::new(Sink::Memory(Vec::new())),
            dropped: AtomicU64::new(0),
        }
    }

    /// Write one event line. `fields` must not contain "ts" or "event"
    /// (they are set here). Never panics; failures increment `dropped`.
    pub fn log(&self, event: &str, fields: Map<String, Value>) {
        let mut obj = Map::new();
        obj.insert(
            "ts".to_string(),
            Value::String(rfc3339_utc(now_unix_ms())),
        );
        obj.insert("event".to_string(), Value::String(event.to_string()));
        for (k, v) in fields {
            obj.insert(k, v);
        }
        let mut line = Value::Object(obj).to_string();
        line.push('\n');
        let ok = match self.sink.lock() {
            Ok(mut sink) => match &mut *sink {
                Sink::File(f) => f.write_all(line.as_bytes()).is_ok(),
                Sink::Stderr => std::io::stderr().write_all(line.as_bytes()).is_ok(),
                Sink::Memory(buf) => {
                    buf.extend_from_slice(line.as_bytes());
                    true
                }
            },
            Err(_) => false,
        };
        if !ok {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Test helper: contents of the memory sink (None for other sinks).
    pub fn memory_contents(&self) -> Option<String> {
        match self.sink.lock() {
            Ok(sink) => match &*sink {
                Sink::Memory(buf) => Some(String::from_utf8_lossy(buf).into_owned()),
                _ => None,
            },
            Err(_) => None,
        }
    }
}

/// Convenience: build a field map from a serde_json object literal.
/// Panics if the value is not an object (programmer error, test-covered).
pub fn fields(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => panic!("audit::fields requires a JSON object"),
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// RFC 3339 UTC timestamps, no external date dependency.
// Algorithm: Howard Hinnant's civil_from_days. Unit-tested against known
// values (including leap years).
// ---------------------------------------------------------------------------

pub fn rfc3339_utc(unix_ms: u64) -> String {
    let secs = (unix_ms / 1000) as i64;
    let millis = unix_ms % 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hh, mm, ss, millis
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), pure implementation, pinned by standard test vectors
// in the test suite. Used for content-free correlation hashes in the audit
// trail (arguments, results, module bytes).
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
