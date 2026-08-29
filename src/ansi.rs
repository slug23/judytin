//! ANSI escape handling: sanitizing what the server may draw with,
//! stripping for trigger matching, mapped reinsertion for
//! highlights/substitutions, and TinTin-style color names.

/// Filter server output down to the escape sequences a MUD legitimately
/// needs, dropping the rest before it reaches the terminal.
///
/// "Colors pass straight through" is a feature; *everything* passing
/// straight through is a vulnerability. A terminal is an interpreter too,
/// and modern ones implement far more than color:
///
/// - `OSC 52` writes the user's clipboard, so a MUD could plant a command
///   there and wait for it to be pasted into a shell.
/// - `OSC 0`/`OSC 21` set and then *report* the window title, and the
///   report arrives on the terminal's input — which this client reads as
///   keystrokes. With a carriage return in it, a hostile server types a
///   command into judytin's input line and presses enter.
/// - DCS, APC and PM carry payloads to the terminal that we have no reason
///   to relay at all.
///
/// So this keeps SGR (`CSI … m`, the colors and attributes) and drops every
/// other escape sequence. Returns the safe text plus any trailing
/// incomplete sequence, which the caller holds until the rest arrives —
/// a sequence split across two TCP packets must not be half-filtered.
pub fn sanitize(text: &str) -> (String, String) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == 0x1b {
            let Some((end, keep)) = escape_extent(bytes, i) else {
                // Incomplete: hand the tail back for next time.
                return (out, text[i..].to_string());
            };
            if keep {
                out.push_str(&text[i..end]);
            }
            i = end;
            continue;
        }
        // Control characters other than the line discipline and tab have no
        // business arriving from a MUD; C1 (U+0080..U+009F) can act as
        // single-byte CSI/OSC introducers on some terminals.
        let ch_len = utf8_len(c);
        let end = (i + ch_len).min(bytes.len());
        let chunk = &text[i..end];
        let keep = match chunk.chars().next() {
            Some(ch) => {
                let n = ch as u32;
                let c0_control = n < 0x20 && !matches!(ch, '\r' | '\n' | '\t');
                let c1_control = (0x80..=0x9f).contains(&n);
                !c0_control && !c1_control
            }
            None => false,
        };
        if keep {
            out.push_str(chunk);
        }
        i = end;
    }
    (out, String::new())
}

/// Find the end of the escape sequence starting at `i`, and whether it is
/// one we relay. `None` means the sequence is not finished yet.
fn escape_extent(bytes: &[u8], i: usize) -> Option<(usize, bool)> {
    match bytes.get(i + 1)? {
        // CSI: parameters, then a final byte. Only SGR ('m') is relayed.
        b'[' => {
            let mut j = i + 2;
            while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                j += 1;
            }
            if j >= bytes.len() {
                return None;
            }
            Some((j + 1, bytes[j] == b'm'))
        }
        // OSC / DCS / APC / PM / SOS: string sequences, terminated by BEL
        // or ST. Never relayed — this is where clipboard and title live.
        b']' | b'P' | b'_' | b'^' | b'X' => {
            let mut j = i + 2;
            while j < bytes.len() {
                if bytes[j] == 0x07 {
                    return Some((j + 1, false));
                }
                if bytes[j] == 0x1b && bytes.get(j + 1) == Some(&b'\\') {
                    return Some((j + 2, false));
                }
                j += 1;
            }
            None
        }
        // Two-byte escapes (ESC 7, ESC 8, ESC c …). Dropped: they move the
        // cursor, reset the terminal, or switch character sets.
        _ => {
            let len = utf8_len(bytes[i + 1]);
            Some(((i + 1 + len).min(bytes.len()), false))
        }
    }
}

/// Strip ANSI escapes from `raw`, returning the plain text plus a map from
/// each plain byte offset (0..=plain.len()) to the corresponding byte offset
/// in `raw`. `map[plain.len()]` points just past the last visible byte, so it
/// is valid as an insertion point.
pub fn strip_map(raw: &str) -> (String, Vec<usize>) {
    let bytes = raw.as_bytes();
    let mut plain = String::with_capacity(raw.len());
    let mut map = Vec::with_capacity(raw.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += 1;
            if i >= bytes.len() {
                break;
            }
            match bytes[i] {
                b'[' => {
                    // CSI: parameters then a final byte in 0x40..=0x7e
                    i += 1;
                    while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                        i += 1;
                    }
                    i += 1; // final byte (or past end)
                }
                b']' => {
                    // OSC: until BEL or ESC \
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\') {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                // ESC 7, ESC 8, etc. Advance by a whole character: the byte
                // after ESC may be the first of a multi-byte one, and
                // landing inside it would slice at a non-boundary below.
                _ => i += utf8_len(bytes[i]),
            }
        } else {
            // copy one UTF-8 character; one map entry per plain byte
            let ch_len = utf8_len(bytes[i]);
            let end = (i + ch_len).min(bytes.len());
            for k in i..end {
                map.push(k);
            }
            plain.push_str(&raw[i..end]);
            i = end;
        }
    }
    map.push(raw.len());
    (plain, map)
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b & 0xe0 == 0xc0 {
        2
    } else if b & 0xf0 == 0xe0 {
        3
    } else if b & 0xf8 == 0xf0 {
        4
    } else {
        1
    }
}

/// Translate a TinTin-style color spec into an SGR escape sequence.
/// Accepts attribute words (light/bold, dim, underscore, blink, reverse),
/// the classic 8 color names plus tt++ extras (azure, ebony, jade, lime,
/// orange, pink, silver, tan, violet), a capitalized name as its light
/// variant ("Red" == "light red"), `b <color>` backgrounds, and `<abc>`
/// color-cube codes with digits a-f. Returns None for words we don't know.
pub fn color_code(spec: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut bright = false;
    let mut bg = false;
    for word in spec.split_whitespace() {
        // <abc> 6x6x6 cube code, tt++ style (a-f = levels 0-5)
        if word.starts_with('<') && word.ends_with('>') && word.len() == 5 {
            let mut levels = [0u16; 3];
            for (i, c) in word[1..4].chars().enumerate() {
                levels[i] = match c {
                    'a'..='f' => c as u16 - 'a' as u16,
                    'A'..='F' => c as u16 - 'A' as u16,
                    '0'..='5' => c as u16 - '0' as u16,
                    _ => return None,
                };
            }
            let n = 16 + 36 * levels[0] + 6 * levels[1] + levels[2];
            parts.push(format!("{};5;{}", if bg { 48 } else { 38 }, n));
            bg = false;
            continue;
        }
        let cap = word.chars().next().is_some_and(|c| c.is_uppercase());
        match word.to_ascii_lowercase().as_str() {
            "light" | "bright" | "bold" => bright = true,
            "dark" => bright = false,
            "b" | "on" | "back" => bg = true,
            "dim" | "faint" => parts.push("2".into()),
            "underscore" | "underline" => parts.push("4".into()),
            "blink" => parts.push("5".into()),
            "reverse" | "inverse" => parts.push("7".into()),
            "reset" => parts.push("0".into()),
            other => {
                let light = bright || cap;
                // classic 8 first: plain SGR codes
                if let Some(base) = match other {
                    "black" => Some(0),
                    "red" => Some(1),
                    "green" => Some(2),
                    "yellow" => Some(3),
                    "blue" => Some(4),
                    "magenta" => Some(5),
                    "cyan" => Some(6),
                    "white" => Some(7),
                    _ => None,
                } {
                    let code = if bg {
                        40 + base
                    } else if light {
                        90 + base
                    } else {
                        30 + base
                    };
                    parts.push(code.to_string());
                } else {
                    // tt++ extras, approximated on the 256-color cube
                    let (dark, lite) = match other {
                        "azure" => (32, 45),
                        "ebony" => (238, 244),
                        "jade" => (35, 49),
                        "lime" => (112, 154),
                        "orange" => (172, 214),
                        "pink" => (204, 218),
                        "silver" => (145, 254),
                        "tan" => (136, 180),
                        "violet" => (99, 141),
                        _ => return None,
                    };
                    let n = if light { lite } else { dark };
                    parts.push(format!("{};5;{}", if bg { 48 } else { 38 }, n));
                }
                bright = false;
                bg = false;
            }
        }
    }
    if bright && parts.is_empty() {
        parts.push("1".into()); // bare "bold"
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("\x1b[{}m", parts.join(";")))
}

pub const RESET: &str = "\x1b[0m";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sgr_and_maps_offsets() {
        let raw = "\x1b[1;33mHello\x1b[0m world";
        let (plain, map) = strip_map(raw);
        assert_eq!(plain, "Hello world");
        // 'H' is at raw offset 7
        assert_eq!(map[0], 7);
        // 'w' (plain offset 6) is after the reset at raw offset 16+1 = 17
        assert_eq!(&raw[map[6]..map[6] + 1], "w");
        assert_eq!(map[plain.len()], raw.len());
    }

    #[test]
    fn plain_text_maps_identity() {
        let (plain, map) = strip_map("abc");
        assert_eq!(plain, "abc");
        assert_eq!(map, vec![0, 1, 2, 3]);
    }

    #[test]
    fn sanitize_keeps_colour_and_drops_everything_else() {
        let (clean, rest) = sanitize("\x1b[1;33mgold\x1b[0m plain");
        assert_eq!(clean, "\x1b[1;33mgold\x1b[0m plain");
        assert!(rest.is_empty());

        // OSC 52 writes the user's clipboard.
        let (clean, _) = sanitize("a\x1b]52;c;cm0gLXJmIH4=\x07b");
        assert_eq!(clean, "ab");
        // OSC terminated by ST rather than BEL.
        let (clean, _) = sanitize("a\x1b]0;title\x1b\\b");
        assert_eq!(clean, "ab");
        // DCS, APC, PM carry payloads we have no reason to relay.
        for intro in ['P', '_', '^', 'X'] {
            let (clean, _) = sanitize(&format!("a\x1b{intro}payload\x1b\\b"));
            assert_eq!(clean, "ab", "intro {intro}");
        }
        // Cursor movement and screen clearing are not ours to hand over.
        let (clean, _) = sanitize("a\x1b[2J\x1b[10;10Hb");
        assert_eq!(clean, "ab");
        // Two-byte escapes (ESC c resets the terminal).
        let (clean, _) = sanitize("a\x1bcb");
        assert_eq!(clean, "ab");
    }

    #[test]
    fn sanitize_holds_a_sequence_split_across_packets() {
        // Half a colour sequence must not be filtered as if complete.
        let (clean, rest) = sanitize("gold\x1b[1;3");
        assert_eq!(clean, "gold");
        assert_eq!(rest, "\x1b[1;3");
        let (clean, rest) = sanitize(&format!("{rest}3mmore"));
        assert_eq!(clean, "\x1b[1;33mmore");
        assert!(rest.is_empty());

        // The same for a string sequence, which must stay suppressed.
        let (clean, rest) = sanitize("a\x1b]52;c;AAA");
        assert_eq!(clean, "a");
        let (clean2, rest2) = sanitize(&format!("{rest}\x07b"));
        assert_eq!(clean2, "b");
        assert!(rest2.is_empty());
    }

    #[test]
    fn sanitize_drops_control_and_c1_characters() {
        let (clean, _) = sanitize("a\u{0}\u{7}b\tc\r\n");
        assert_eq!(clean, "ab\tc\r\n");
        // C1 introducers act as CSI/OSC on some terminals.
        let (clean, _) = sanitize("a\u{9b}31mb\u{9d}52;x\u{9c}c");
        assert_eq!(clean, "a31mb52;xc");
    }

    #[test]
    fn sanitize_preserves_ordinary_text_including_unicode() {
        let text = "The guard nods — “well met”, he says. ök ✓";
        let (clean, rest) = sanitize(text);
        assert_eq!(clean, text);
        assert!(rest.is_empty());
    }

    #[test]
    fn lone_escape_before_multibyte_does_not_split_a_character() {
        // A hostile (or merely sloppy) server can send ESC followed by a
        // multi-byte character. Advancing one byte would land mid-character
        // and panic the client on the next slice.
        let raw = "hello \x1bé world";
        let (plain, map) = strip_map(raw);
        assert!(plain.ends_with(" world"), "plain: {plain:?}");
        assert_eq!(map.len(), plain.len() + 1);
        for (n, &offset) in map.iter().enumerate() {
            assert!(
                raw.is_char_boundary(offset),
                "map[{n}] = {offset} is not a char boundary"
            );
        }
    }

    #[test]
    fn truncated_escapes_do_not_panic() {
        for raw in ["\x1b", "\x1b[", "\x1b[3", "\x1b]", "\x1b]0;t", "\x1bé", "é\x1b"] {
            let (plain, map) = strip_map(raw);
            assert_eq!(map.len(), plain.len() + 1, "raw: {raw:?}");
        }
    }

    #[test]
    fn handles_utf8() {
        let raw = "\x1b[31mnöö\x1b[0m";
        let (plain, map) = strip_map(raw);
        assert_eq!(plain, "nöö");
        assert_eq!(map[0], 5);
        assert_eq!(map.len(), plain.len() + 1);
    }

    #[test]
    fn color_names() {
        assert_eq!(color_code("red").unwrap(), "\x1b[31m");
        assert_eq!(color_code("light yellow").unwrap(), "\x1b[93m");
        assert_eq!(color_code("bold").unwrap(), "\x1b[1m");
        assert_eq!(color_code("reverse").unwrap(), "\x1b[7m");
        assert_eq!(color_code("underscore green").unwrap(), "\x1b[4;32m");
        assert!(color_code("mauve").is_none());
    }

    #[test]
    fn tt_color_extras() {
        // capitalized name = light variant
        assert_eq!(color_code("Red").unwrap(), "\x1b[91m");
        assert_eq!(color_code("orange").unwrap(), "\x1b[38;5;172m");
        assert_eq!(color_code("Orange").unwrap(), "\x1b[38;5;214m");
        // <abc> cube codes: f,0,0 -> 16 + 36*5 = 196
        assert_eq!(color_code("<faa>").unwrap(), "\x1b[38;5;196m");
        assert_eq!(color_code("<fff>").unwrap(), "\x1b[38;5;231m");
        assert_eq!(color_code("b <aaf>").unwrap(), "\x1b[48;5;21m");
        assert!(color_code("<zzz>").is_none());
    }
}
