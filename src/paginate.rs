//! Stateless, tamper-evident cursors for the client-facing `tools/list`.
//!
//! Design constraints, straight from toolcage's model:
//!
//!  - **Stateless like the sandbox.** Every `tools/call` runs in a fresh
//!    instance with nothing carried over implicitly; pagination follows the
//!    same discipline. There is no server-side cursor registry — the entire
//!    page position lives *inside* the opaque cursor. Losing or duplicating a
//!    cursor cannot corrupt any shared state, because there is none.
//!
//!  - **Filter before paging.** The page is always sliced from the
//!    already-policy-filtered visible list. A denied or unlisted-denied tool
//!    is unreachable from *any* cursor value, valid or forged — pagination
//!    never sees it in the first place. This preserves the existing
//!    `tools/list` filtering guarantee byte-for-byte.
//!
//!  - **Opaque yet tamper-evident.** MCP requires cursors be opaque to the
//!    client. toolcage's are also authenticated: a per-process ephemeral key
//!    signs each cursor, and the cursor is bound to a snapshot id of the exact
//!    ordered visible tool set it was minted from. Any edit, truncation,
//!    cross-session reuse, or restart-stale cursor fails verification and is
//!    rejected with JSON-RPC `-32602`, never silently mis-paginated. This is
//!    defense-in-depth: because pages are re-derived from the filtered set, a
//!    forged cursor could at worst name a valid page — never reveal a hidden
//!    tool — but rejecting garbage cleanly keeps the contract honest and the
//!    audit trail meaningful.
//!
//! Wire format (opaque to clients; documented here for auditors):
//! ```text
//!   cursor := "tc1." base64url( body || tag )
//!   body   := offset_be(4) || snapshot_id(8)          // 12 bytes
//!   tag    := HMAC-SHA256(key, body)[..16]            // 16 bytes
//! ```
//! The key is generated once per `toolcage run` process and never persisted,
//! so cursors do not survive a restart — matching MCP's guidance that a server
//! may treat a cursor as invalid once it can no longer honor it.

use crate::audit::sha256;

/// Cursor scheme version tag. Bump if the wire format ever changes so old
/// cursors are rejected as malformed rather than misread.
const CURSOR_PREFIX: &str = "tc1.";
const OFFSET_LEN: usize = 4;
const SNAPSHOT_LEN: usize = 8;
const TAG_LEN: usize = 16;
const BODY_LEN: usize = OFFSET_LEN + SNAPSHOT_LEN;
const RAW_LEN: usize = BODY_LEN + TAG_LEN;

/// Why a client-supplied cursor was rejected. All map to JSON-RPC `-32602`;
/// the variant is recorded (content-free) in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    /// Bad prefix, bad base64, or wrong length — not a cursor toolcage minted.
    Malformed,
    /// Structure is right but the authentication tag does not verify: the
    /// cursor was tampered with, or was minted by a different process/key
    /// (e.g. after a restart).
    BadMac,
    /// Authenticated, but bound to a different tool-set snapshot than this
    /// session's — the visible registry changed, or it is a foreign session's
    /// cursor.
    Snapshot,
    /// Authenticated and snapshot-matched, but the offset is not an interior
    /// page boundary this paginator could have emitted.
    OutOfRange,
}

impl CursorError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CursorError::Malformed => "malformed",
            CursorError::BadMac => "bad_mac",
            CursorError::Snapshot => "snapshot_mismatch",
            CursorError::OutOfRange => "out_of_range",
        }
    }
}

/// One page of the visible tool list: the half-open slice `[start, end)` plus
/// an optional cursor for the following page (present iff more tools remain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub start: usize,
    pub end: usize,
    pub next_cursor: Option<String>,
}

/// Pages a stable, ordered, already-policy-filtered tool list.
///
/// Construct one per `tools/list` request from the current visible names. It
/// holds no state between requests; the snapshot id and total are derived from
/// the names alone, so two requests over the same visible set produce
/// identical, interchangeable cursors.
pub struct Paginator {
    key: [u8; 32],
    snapshot_id: [u8; SNAPSHOT_LEN],
    /// Tools per page. `0` disables pagination entirely (one unlimited page,
    /// no cursor ever emitted) — the pre-pagination behavior, preserved for
    /// backward compatibility.
    page_size: usize,
    total: usize,
}

impl Paginator {
    pub fn new(key: [u8; 32], visible_names: &[&str], page_size: usize) -> Paginator {
        Paginator {
            key,
            snapshot_id: snapshot_id(visible_names),
            page_size,
            total: visible_names.len(),
        }
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// Resolve a request's optional cursor into the page to serve.
    ///
    /// `None` (or any cursor when pagination is disabled) yields the first
    /// page. An invalid, tampered, expired, or foreign cursor is rejected.
    pub fn page(&self, cursor: Option<&str>) -> Result<Page, CursorError> {
        // Disabled: one unlimited page. A cursor is ignored rather than
        // rejected, because no cursor is ever issued in this mode and the
        // pre-pagination endpoint simply ignored unknown params. Returning the
        // full (already-filtered) list is never a disclosure.
        if self.page_size == 0 {
            return Ok(Page {
                start: 0,
                end: self.total,
                next_cursor: None,
            });
        }

        let start = match cursor {
            None => 0,
            Some(c) => self.decode(c)?,
        };
        let end = start.saturating_add(self.page_size).min(self.total);
        let next_cursor = if end < self.total {
            Some(self.encode(end))
        } else {
            None
        };
        Ok(Page {
            start,
            end,
            next_cursor,
        })
    }

    fn encode(&self, offset: usize) -> String {
        let mut body = Vec::with_capacity(BODY_LEN);
        body.extend_from_slice(&(offset as u32).to_be_bytes());
        body.extend_from_slice(&self.snapshot_id);
        let tag = hmac_sha256(&self.key, &body);
        let mut raw = body;
        raw.extend_from_slice(&tag[..TAG_LEN]);
        let mut s = String::from(CURSOR_PREFIX);
        s.push_str(&b64url_encode(&raw));
        s
    }

    fn decode(&self, cursor: &str) -> Result<usize, CursorError> {
        let b64 = cursor
            .strip_prefix(CURSOR_PREFIX)
            .ok_or(CursorError::Malformed)?;
        let raw = b64url_decode(b64).ok_or(CursorError::Malformed)?;
        if raw.len() != RAW_LEN {
            return Err(CursorError::Malformed);
        }
        let (body, tag) = raw.split_at(BODY_LEN);
        let expect = hmac_sha256(&self.key, body);
        if !ct_eq(&expect[..TAG_LEN], tag) {
            return Err(CursorError::BadMac);
        }
        if body[OFFSET_LEN..BODY_LEN] != self.snapshot_id {
            return Err(CursorError::Snapshot);
        }
        let offset = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        // Must be an interior page boundary this paginator could have emitted:
        // a positive multiple of page_size strictly less than total. The MAC
        // already guarantees this for cursors we minted; the check is a guard
        // against a page-size change or internal misuse.
        if offset == 0 || offset >= self.total || !offset.is_multiple_of(self.page_size) {
            return Err(CursorError::OutOfRange);
        }
        Ok(offset)
    }
}

/// Snapshot id: a short digest binding a cursor to the exact ordered set of
/// visible tool names. Length-prefixed framing so `["ab","c"]` and `["a","bc"]`
/// can never collide.
fn snapshot_id(names: &[&str]) -> [u8; SNAPSHOT_LEN] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(names.len() as u64).to_le_bytes());
    for n in names {
        buf.extend_from_slice(&(n.len() as u64).to_le_bytes());
        buf.extend_from_slice(n.as_bytes());
    }
    let d = sha256(&buf);
    let mut id = [0u8; SNAPSHOT_LEN];
    id.copy_from_slice(&d[..SNAPSHOT_LEN]);
    id
}

/// Constant-time byte-slice equality, so tag verification does not leak where
/// a mismatch occurred through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256 (RFC 2104) over the repo's existing pure SHA-256. Our key is
/// always 32 bytes, so the `> block` branch is dead but kept correct.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_digest = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

// ---------------------------------------------------------------------------
// base64url without padding (RFC 4648 §5). Strict decoder: rejects invalid
// characters, impossible lengths, and non-canonical trailing bits, so a
// mangled cursor never decodes to a plausible-but-wrong byte string.
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64url_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    // A base64 unit is 4 chars -> 3 bytes; a remainder of exactly 1 char is
    // impossible (would encode < 6 bits of a byte).
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in bytes {
        let v = b64url_val(c)?;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    // Leftover partial bits must be zero for a canonical no-padding encoding.
    if nbits > 0 && (acc & ((1u32 << nbits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ---- primitives --------------------------------------------------------

    #[test]
    fn hmac_matches_rfc4231_case1() {
        // RFC 4231 Test Case 1: key = 0x0b*20, data = "Hi There".
        let out = hmac_sha256(&[0x0b; 20], b"Hi There");
        let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(out.to_vec(), expected);
    }

    #[test]
    fn base64url_roundtrips_and_pins_a_vector() {
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url_decode("Zm9vYmFy").unwrap(), b"foobar");
        for len in 0..40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37) ^ 0x5a)
                .collect();
            let enc = b64url_encode(&data);
            assert_eq!(b64url_decode(&enc).unwrap(), data, "roundtrip len {}", len);
        }
        // url-safe alphabet: 0xff 0xff -> "__8", never '+' or '/'.
        assert_eq!(b64url_encode(&[0xff, 0xff]), "__8");
        assert!(!b64url_encode(&[0xfb, 0xf0]).contains(['+', '/']));
    }

    #[test]
    fn base64url_rejects_bad_input() {
        assert!(b64url_decode("****").is_none()); // invalid chars
        assert!(b64url_decode("A").is_none()); // impossible length (len%4==1)
        assert!(b64url_decode("Zm9vYmF+").is_none()); // '+' is not url-safe
                                                      // Non-canonical trailing bits: "__" decodes 12 bits, low 4 must be 0.
        assert!(b64url_decode("__").is_none());
        assert_eq!(b64url_decode("_w").unwrap(), vec![0xff]); // canonical single byte
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- snapshot binding --------------------------------------------------

    #[test]
    fn snapshot_id_distinguishes_sets_and_order() {
        assert_ne!(snapshot_id(&["a", "b"]), snapshot_id(&["a", "c"]));
        assert_ne!(snapshot_id(&["a", "b"]), snapshot_id(&["b", "a"]));
        assert_ne!(snapshot_id(&["ab", "c"]), snapshot_id(&["a", "bc"]));
        assert_eq!(snapshot_id(&["a", "b"]), snapshot_id(&["a", "b"]));
    }

    // ---- paging arithmetic -------------------------------------------------

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("t{}", i)).collect()
    }
    fn refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn empty_list_is_a_single_empty_page() {
        let p = Paginator::new(key(1), &[], 2);
        let page = p.page(None).unwrap();
        assert_eq!(
            page,
            Page {
                start: 0,
                end: 0,
                next_cursor: None
            }
        );
    }

    #[test]
    fn single_page_when_total_fits() {
        let n = names(2);
        let p = Paginator::new(key(1), &refs(&n), 2);
        let page = p.page(None).unwrap();
        assert_eq!(page.start, 0);
        assert_eq!(page.end, 2);
        assert!(page.next_cursor.is_none(), "no cursor when everything fits");
    }

    #[test]
    fn exact_boundary_emits_no_trailing_empty_page() {
        // total == 2*page_size: two full pages, the second must not offer a
        // (would-be empty) third.
        let n = names(4);
        let p = Paginator::new(key(1), &refs(&n), 2);
        let p1 = p.page(None).unwrap();
        assert_eq!((p1.start, p1.end), (0, 2));
        let c1 = p1.next_cursor.expect("page 1 has a next cursor");
        let p2 = p.page(Some(&c1)).unwrap();
        assert_eq!((p2.start, p2.end), (2, 4));
        assert!(
            p2.next_cursor.is_none(),
            "no empty third page at the boundary"
        );
    }

    #[test]
    fn walks_a_ragged_last_page_exactly_once() {
        let n = names(5);
        let p = Paginator::new(key(1), &refs(&n), 2);
        let mut cursor: Option<String> = None;
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let page = p.page(cursor.as_deref()).unwrap();
            seen.extend(page.start..page.end);
            pages += 1;
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
            assert!(pages < 10, "must terminate");
        }
        assert_eq!(seen, vec![0, 1, 2, 3, 4], "every index once, in order");
        assert_eq!(pages, 3, "2 + 2 + 1");
    }

    #[test]
    fn disabled_page_size_returns_everything_and_ignores_cursor() {
        let n = names(100);
        let p = Paginator::new(key(1), &refs(&n), 0);
        let page = p.page(None).unwrap();
        assert_eq!((page.start, page.end), (0, 100));
        assert!(page.next_cursor.is_none());
        // A stray cursor is ignored, not an error, in disabled mode.
        let page = p.page(Some("tc1.whatever")).unwrap();
        assert_eq!((page.start, page.end), (0, 100));
    }

    // ---- cursor integrity --------------------------------------------------

    #[test]
    fn roundtrips_a_minted_cursor() {
        let n = names(5);
        let p = Paginator::new(key(7), &refs(&n), 2);
        let c = p.page(None).unwrap().next_cursor.unwrap();
        assert_eq!(p.decode(&c).unwrap(), 2);
    }

    #[test]
    fn rejects_malformed_cursors() {
        let n = names(5);
        let p = Paginator::new(key(7), &refs(&n), 2);
        assert_eq!(p.page(Some("garbage")).unwrap_err(), CursorError::Malformed);
        assert_eq!(p.page(Some("tc1.")).unwrap_err(), CursorError::Malformed);
        assert_eq!(
            p.page(Some("tc1.****")).unwrap_err(),
            CursorError::Malformed
        );
        assert_eq!(p.page(Some("xx.AAAA")).unwrap_err(), CursorError::Malformed);
        // right prefix, valid base64, but wrong length.
        assert_eq!(
            p.page(Some("tc1.AAAA")).unwrap_err(),
            CursorError::Malformed
        );
    }

    #[test]
    fn rejects_a_tampered_cursor() {
        let n = names(5);
        let p = Paginator::new(key(7), &refs(&n), 2);
        let c = p.page(None).unwrap().next_cursor.unwrap();
        // Flip the last base64 char (part of the tag).
        let mut bytes: Vec<char> = c.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = bytes.into_iter().collect();
        assert_eq!(p.page(Some(&tampered)).unwrap_err(), CursorError::BadMac);
    }

    #[test]
    fn rejects_a_foreign_key_cursor() {
        // Same tool set, cursor minted under a different process key: this is
        // the "expired after restart" case.
        let n = names(5);
        let minted = Paginator::new(key(7), &refs(&n), 2)
            .page(None)
            .unwrap()
            .next_cursor
            .unwrap();
        let other = Paginator::new(key(8), &refs(&n), 2);
        assert_eq!(other.page(Some(&minted)).unwrap_err(), CursorError::BadMac);
    }

    #[test]
    fn rejects_a_foreign_snapshot_cursor() {
        // Same key, but the visible tool set changed out from under the cursor.
        let a = names(5);
        let minted = Paginator::new(key(7), &refs(&a), 2)
            .page(None)
            .unwrap()
            .next_cursor
            .unwrap();
        let b = names(6); // different set -> different snapshot id
        let other = Paginator::new(key(7), &refs(&b), 2);
        assert_eq!(
            other.page(Some(&minted)).unwrap_err(),
            CursorError::Snapshot
        );
    }

    #[test]
    fn rejects_an_out_of_range_offset() {
        // A cursor whose offset equals total is one the paginator would never
        // emit (that page is empty); reject it even though it authenticates.
        let n = names(4);
        let p = Paginator::new(key(7), &refs(&n), 2);
        let forged = p.encode(p.total); // offset == total, valid MAC + snapshot
        assert_eq!(p.decode(&forged).unwrap_err(), CursorError::OutOfRange);
    }
}
