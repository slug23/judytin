//! The local UTC offset, read from the system's own timezone database.
//!
//! judytin rendered `%t` in UTC because it had no timezone data and would not
//! take a dependency for one. The data is already on the machine, though, in
//! the format every Unix ships: TZif (RFC 8536), at `/etc/localtime`. Parsing
//! the part that answers "what is the offset right now" is a hundred lines,
//! which is cheaper than a crate and cheaper still than being quietly wrong
//! about what time it is.
//!
//! Only what is needed is parsed: transition times, which type each period
//! uses, and each type's offset and abbreviation. Leap seconds, standard/wall
//! indicators and the POSIX footer rule are skipped — the footer matters only
//! for dates past the end of the transition table, which real files carry well
//! beyond any plausible `now`.
//!
//! Anything unreadable or malformed falls back to UTC rather than guessing. A
//! wrong offset is worse than an honest zero.

use std::sync::OnceLock;

/// One period's offset from UTC and what to call it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ttype {
    utoff: i32,
    abbr: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Tz {
    /// Ascending instants, in seconds since the epoch, at which the offset changes.
    transitions: Vec<i64>,
    /// Which type applies from each transition onward. Same length as above.
    idx: Vec<u8>,
    types: Vec<Ttype>,
}

impl Tz {
    /// The offset and abbreviation in force at `t`.
    fn at(&self, t: i64) -> Option<&Ttype> {
        // partition_point gives the count of transitions at or before t, so
        // subtracting one lands on the period containing t.
        let n = self.transitions.partition_point(|&x| x <= t);
        if n == 0 {
            // Before the first recorded transition. The convention is the
            // first type that is not daylight saving; these files list it
            // first, and falling back to index 0 is what other readers do.
            return self.types.first();
        }
        self.types.get(*self.idx.get(n - 1)? as usize)
    }
}

fn be32(b: &[u8]) -> i32 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> i64 {
    i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Parse one TZif data block. `wide` selects 8-byte transition times, which is
/// what the version 2 block uses. Returns the block and how many bytes it took,
/// so the caller can step over a version 1 block to reach the better one.
fn parse_block(b: &[u8], wide: bool) -> Option<(Tz, usize)> {
    if b.len() < 44 || &b[..4] != b"TZif" {
        return None;
    }
    // Six counts follow the sixteen reserved bytes. The length check above
    // guarantees all of them are present.
    let count = |i: usize| be32(&b[20 + i * 4..24 + i * 4]).max(0) as usize;
    let (isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt) =
        (count(0), count(1), count(2), count(3), count(4), count(5));
    if typecnt == 0 {
        return None;
    }
    let tsize = if wide { 8 } else { 4 };
    let lsize = if wide { 12 } else { 8 };
    let need = 44
        + timecnt * tsize
        + timecnt
        + typecnt * 6
        + charcnt
        + leapcnt * lsize
        + isstdcnt
        + isutcnt;
    if b.len() < need {
        return None;
    }

    let mut p = 44;
    let mut transitions = Vec::with_capacity(timecnt);
    for _ in 0..timecnt {
        transitions.push(if wide {
            be64(&b[p..p + 8])
        } else {
            be32(&b[p..p + 4]) as i64
        });
        p += tsize;
    }
    let idx = b[p..p + timecnt].to_vec();
    p += timecnt;

    let ttinfo_at = p;
    p += typecnt * 6;
    let chars = &b[p..p + charcnt];

    let mut types = Vec::with_capacity(typecnt);
    for i in 0..typecnt {
        let o = ttinfo_at + i * 6;
        let utoff = be32(&b[o..o + 4]);
        let desig = b[o + 5] as usize;
        // Designations are NUL-terminated strings packed end to end, indexed
        // by byte offset rather than by number.
        let abbr = chars
            .get(desig..)
            .and_then(|s| s.split(|&c| c == 0).next())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        types.push(Ttype { utoff, abbr });
    }

    // Any type index that does not name a type would make `at` silently
    // choose the wrong offset, so refuse the file instead.
    if idx.iter().any(|&i| i as usize >= typecnt) {
        return None;
    }

    Some((Tz { transitions, idx, types }, need))
}

fn parse_tzif(b: &[u8]) -> Option<Tz> {
    let version = *b.get(4)?;
    let (v1, used) = parse_block(b, false)?;
    if version == 0 {
        return Some(v1);
    }
    // Version 2 and up repeat everything with 64-bit times. Prefer that block:
    // the 32-bit one runs out in 2038 and some files stub it out entirely.
    match parse_block(b.get(used..)?, true) {
        Some((v2, _)) if !v2.types.is_empty() => Some(v2),
        _ => Some(v1),
    }
}

/// Where the system keeps the zone judytin should use.
///
/// `TZ` is the player's own environment, never server text, so honouring a
/// path in it grants a MUD nothing. An unset or unusable value falls through
/// to the system default rather than failing.
fn tz_path() -> std::path::PathBuf {
    if let Ok(tz) = std::env::var("TZ") {
        let tz = tz.strip_prefix(':').unwrap_or(&tz);
        if !tz.is_empty() {
            let p = std::path::Path::new(tz);
            if p.is_absolute() {
                return p.to_path_buf();
            }
            // Reject anything that could climb out of the zone directory. A
            // relative TZ is a zone name like "Europe/Lisbon", nothing more.
            if !tz.contains("..") {
                return std::path::Path::new("/usr/share/zoneinfo").join(tz);
            }
        }
    }
    std::path::PathBuf::from("/etc/localtime")
}

/// Read and parse the zone once. Failure is remembered as "UTC" so a missing
/// or broken file is not re-read on every timestamp.
fn zone() -> Option<&'static Tz> {
    static ZONE: OnceLock<Option<Tz>> = OnceLock::new();
    ZONE.get_or_init(|| std::fs::read(tz_path()).ok().and_then(|b| parse_tzif(&b)))
        .as_ref()
}

/// Seconds east of UTC at `t`, and what the zone calls itself then.
/// `(0, "UTC")` when the system cannot say.
pub fn local_at(t: i64) -> (i32, String) {
    match zone().and_then(|z| z.at(t)) {
        Some(ty) if !ty.abbr.is_empty() => (ty.utoff, ty.abbr.clone()),
        Some(ty) => (ty.utoff, offset_name(ty.utoff)),
        None => (0, "UTC".to_string()),
    }
}

/// `+hhmm`, the shape `%z` wants.
pub fn offset_name(secs: i32) -> String {
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.abs();
    format!("{}{:02}{:02}", sign, a / 3600, (a % 3600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built TZif version 1 file: one transition, two types.
    fn synthetic() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"TZif");
        b.push(0); // version 1
        b.extend_from_slice(&[0u8; 15]);
        for n in [0u32, 0, 0, 1, 2, 8] {
            b.extend_from_slice(&n.to_be_bytes()); // isut isstd leap time type char
        }
        b.extend_from_slice(&1_000_000i32.to_be_bytes()); // one transition
        b.push(1); // ...into type 1
        // type 0: +0000 "GMT"
        b.extend_from_slice(&0i32.to_be_bytes());
        b.push(0);
        b.push(0);
        // type 1: +0100 "BST"
        b.extend_from_slice(&3600i32.to_be_bytes());
        b.push(1);
        b.push(4);
        b.extend_from_slice(b"GMT\0BST\0");
        b
    }

    #[test]
    fn a_transition_changes_the_offset() {
        let tz = parse_tzif(&synthetic()).expect("should parse");
        assert_eq!(tz.at(999_999).unwrap(), &Ttype { utoff: 0, abbr: "GMT".into() });
        assert_eq!(tz.at(1_000_000).unwrap(), &Ttype { utoff: 3600, abbr: "BST".into() });
        assert_eq!(tz.at(9_999_999).unwrap(), &Ttype { utoff: 3600, abbr: "BST".into() });
    }

    #[test]
    fn rubbish_is_refused_rather_than_guessed_at() {
        assert!(parse_tzif(b"").is_none());
        assert!(parse_tzif(b"NOTTZif and then some padding to get past the header").is_none());
        // Truncated after the header: the counts promise data that is not there.
        let mut short = synthetic();
        short.truncate(50);
        assert!(parse_tzif(&short).is_none());
    }

    #[test]
    fn a_type_index_past_the_end_is_refused() {
        // Left unchecked this would read the wrong offset, or panic.
        let mut b = synthetic();
        b[44 + 4] = 9; // the single transition now names a type that is not there
        assert!(parse_tzif(&b).is_none());
    }

    #[test]
    fn offsets_render_the_way_percent_z_wants() {
        assert_eq!(offset_name(0), "+0000");
        assert_eq!(offset_name(3600), "+0100");
        assert_eq!(offset_name(-18000), "-0500");
        assert_eq!(offset_name(19800), "+0530"); // half-hour zones exist
        assert_eq!(offset_name(-1800), "-0030");
    }

    #[test]
    fn a_missing_zone_is_utc_and_not_a_crash() {
        // local_at cannot be pointed at a fixture (the zone is read once per
        // process), but it must always answer.
        let (off, name) = local_at(0);
        assert!((-50400..=50400).contains(&off), "implausible offset {off}");
        assert!(!name.is_empty());
    }
}
