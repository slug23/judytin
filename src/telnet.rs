//! Telnet byte-stream parser.
//!
//! judymud speaks plain text and never negotiates, but other MUDs do, so we
//! run a proper IAC state machine: strip everything, refuse every option we
//! are offered, and never volunteer one ourselves. The single exception is
//! server-side ECHO (used for password prompts elsewhere), which we accept
//! and surface as a flag so the UI can mask the input line.
//!
//! Crucially we never send subnegotiations: judymud treats `IAC SB` as a
//! two-byte command, so an SB payload would leak into its command parser.

const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Data,
    Iac,
    Opt(u8),
    Sb,
    SbIac,
}

pub struct Telnet {
    state: State,
    /// True while the server has claimed ECHO (hide what the user types).
    pub server_echo: bool,
}

impl Telnet {
    pub fn new() -> Self {
        Telnet { state: State::Data, server_echo: false }
    }

    /// Feed raw socket bytes; returns (application data, bytes to send back).
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut data = Vec::with_capacity(input.len());
        let mut reply = Vec::new();
        for &b in input {
            match self.state {
                State::Data => {
                    if b == IAC {
                        self.state = State::Iac;
                    } else {
                        data.push(b);
                    }
                }
                State::Iac => match b {
                    IAC => {
                        data.push(IAC);
                        self.state = State::Data;
                    }
                    WILL | WONT | DO | DONT => self.state = State::Opt(b),
                    SB => self.state = State::Sb,
                    _ => self.state = State::Data, // NOP, GA, EOR, ...
                },
                State::Opt(cmd) => {
                    match (cmd, b) {
                        (WILL, OPT_ECHO) => {
                            if !self.server_echo {
                                self.server_echo = true;
                                reply.extend_from_slice(&[IAC, DO, OPT_ECHO]);
                            }
                        }
                        (WONT, OPT_ECHO) => {
                            if self.server_echo {
                                self.server_echo = false;
                                reply.extend_from_slice(&[IAC, DONT, OPT_ECHO]);
                            }
                        }
                        (WILL, OPT_SGA) => reply.extend_from_slice(&[IAC, DO, OPT_SGA]),
                        (WILL, opt) => reply.extend_from_slice(&[IAC, DONT, opt]),
                        (DO, opt) => reply.extend_from_slice(&[IAC, WONT, opt]),
                        _ => {} // WONT/DONT of things we never asked for
                    }
                    self.state = State::Data;
                }
                State::Sb => {
                    if b == IAC {
                        self.state = State::SbIac;
                    }
                }
                State::SbIac => match b {
                    SE => self.state = State::Data,
                    IAC => self.state = State::Sb, // escaped 0xFF inside SB
                    _ => self.state = State::Sb,
                },
            }
        }
        (data, reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        let mut t = Telnet::new();
        let (d, r) = t.feed(b"hello\r\nworld");
        assert_eq!(d, b"hello\r\nworld");
        assert!(r.is_empty());
    }

    #[test]
    fn refuses_unknown_options() {
        let mut t = Telnet::new();
        // IAC WILL 86 (MCCP2), IAC DO 31 (NAWS)
        let (d, r) = t.feed(&[IAC, WILL, 86, b'x', IAC, DO, 31]);
        assert_eq!(d, b"x");
        assert_eq!(r, vec![IAC, DONT, 86, IAC, WONT, 31]);
    }

    #[test]
    fn accepts_echo_and_sets_flag() {
        let mut t = Telnet::new();
        let (_, r) = t.feed(&[IAC, WILL, OPT_ECHO]);
        assert_eq!(r, vec![IAC, DO, OPT_ECHO]);
        assert!(t.server_echo);
        let (_, r) = t.feed(&[IAC, WONT, OPT_ECHO]);
        assert_eq!(r, vec![IAC, DONT, OPT_ECHO]);
        assert!(!t.server_echo);
    }

    #[test]
    fn swallows_subnegotiation() {
        let mut t = Telnet::new();
        let (d, r) = t.feed(&[b'a', IAC, SB, 24, 1, 2, IAC, IAC, 3, IAC, SE, b'b']);
        assert_eq!(d, b"ab");
        assert!(r.is_empty());
    }

    #[test]
    fn escaped_iac_is_literal() {
        let mut t = Telnet::new();
        let (d, _) = t.feed(&[b'a', IAC, IAC, b'b']);
        assert_eq!(d, &[b'a', 255, b'b']);
    }

    #[test]
    fn split_across_feeds() {
        let mut t = Telnet::new();
        let (d1, r1) = t.feed(&[b'a', IAC]);
        let (d2, r2) = t.feed(&[WILL]);
        let (d3, r3) = t.feed(&[86, b'b']);
        assert_eq!(d1, b"a");
        assert!(d2.is_empty() && r1.is_empty() && r2.is_empty());
        assert_eq!(d3, b"b");
        assert_eq!(r3, vec![IAC, DONT, 86]);
    }
}
