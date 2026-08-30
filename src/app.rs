//! Session state, the input/output pipelines, and interpreter plumbing.
//! The # command implementations live in commands.rs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crate::ansi::strip_map;
use crate::net::{self, Conn, Pin};
use crate::pattern;
use crate::script;
use crate::telnet::Telnet;
use crate::ui::SplitUi;

pub const MAX_DEPTH: u32 = 64;

/// Longest line we will accumulate before forcing it out for display.
///
/// Two hostile shapes need this: a server that never sends a newline (the
/// buffer would grow until the client is killed), and one that sends a very
/// long line (trigger matching costs more than linear in the line length,
/// so a single huge line freezes the single-threaded event loop). No real
/// MUD line approaches this.
pub const MAX_LINE: usize = 8 * 1024;

#[allow(clippy::large_enum_variant)]
pub enum Ev {
    Key(crossterm::event::KeyEvent),
    Resize(u16, u16),
    Line(String),
    StdinEof,
    Net(u64, Vec<u8>),
    NetClosed(u64, String),
    /// judytin's own note about the connection — never server text, so it is
    /// shown as an info line and never fed to the trigger engine.
    NetDiag(u64, String),
}

/// How to get back to where we were.
///
/// Kept after the socket goes, which is the whole point: a disconnect throws
/// away the connection but not the knowledge of how it was made, so
/// `#reconnect` and the automatic retry have somewhere to aim without the
/// player retyping a `#session` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Recipe {
    Tcp { host: String, port: u16 },
    Tls { host: String, port: u16 },
    Pipe { label: String, command: String, ssh: Option<String> },
}

impl Recipe {
    /// How it reads back to the player, in the words they used to make it.
    pub(crate) fn describe(&self) -> String {
        match self {
            Recipe::Tcp { host, port } => format!("{}:{}", host, port),
            Recipe::Tls { host, port } => format!("{}:{} (tls)", host, port),
            Recipe::Pipe { label, .. } => format!("{} (pipe)", label),
        }
    }

    /// Read a destination the way a person writes one.
    ///
    /// `host`, `host:port`, or a scheme that names the transport:
    /// `tcp://`, `telnet://`, `ssl://`, `tls://`, `ssh://`. This is what lets
    /// `#session` open every transport judytin has, instead of one verb per
    /// transport with a different argument shape each. The vocabulary is the
    /// one `--tls` and `--ssh` already use, so it is not a second thing to
    /// learn, and the port each scheme defaults to is the same door judymud
    /// answers on.
    ///
    /// `port` is the separate third argument of the classic
    /// `#session {name} {host} {port}` form. Given, it wins: it is the more
    /// deliberate way to type a port than tucking one inside a destination.
    pub(crate) fn parse(dest: &str, port: Option<u16>) -> Result<Recipe, String> {
        let dest = dest.trim();
        if dest.is_empty() {
            return Err("no host to connect to".to_string());
        }
        let (scheme, rest) = match dest.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => (String::new(), dest),
        };
        // ssh is not a host and a port: it is a destination ssh itself parses,
        // and its port belongs on ssh's own command line.
        if scheme == "ssh" {
            if rest.is_empty() {
                return Err("ssh:// needs a destination, e.g. ssh://you@mudhost".to_string());
            }
            let d = match port {
                // A port typed as the third argument replaces one written into
                // the destination, rather than producing two of them.
                Some(p) => {
                    let base = match rest.rsplit_once(':') {
                        Some((h, t)) if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) => h,
                        _ => rest,
                    };
                    format!("{}:{}", base, p)
                }
                None => rest.to_string(),
            };
            return Ok(Recipe::Pipe {
                label: d.clone(),
                command: crate::net::ssh_command(&d),
                ssh: Some(d),
            });
        }
        let (host, embedded) = split_host_port(rest)?;
        if host.is_empty() {
            return Err(format!("'{}' has no host in it", dest));
        }
        let default = match scheme.as_str() {
            "ssl" | "tls" => 2324,
            _ => 2323,
        };
        let port = port.or(embedded).unwrap_or(default);
        match scheme.as_str() {
            "" | "tcp" | "telnet" => Ok(Recipe::Tcp { host, port }),
            "ssl" | "tls" => Ok(Recipe::Tls { host, port }),
            other => Err(format!(
                "'{}://' is not a transport judytin has (tcp telnet ssl tls ssh)",
                other
            )),
        }
    }
}

/// Split `host`, `host:port` or `[v6]:port` without mistaking a bare IPv6
/// address for one. `::1` is a host; `::1:80` is still a host, because the
/// only way to put a port on an IPv6 address is to bracket it.
fn split_host_port(s: &str) -> Result<(String, Option<u16>), String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, "")) => (h, None),
            Some((h, tail)) => match tail.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None => return Err(format!("'{}' has junk after the address", s)),
            },
            None => return Err(format!("'{}' opens a bracket it never closes", s)),
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && !p.is_empty() => (h, Some(p)),
            _ => (s, None),
        }
    };
    match port {
        None => Ok((host.to_string(), None)),
        Some(p) => match p.parse::<u16>() {
            Ok(n) => Ok((host.to_string(), Some(n))),
            Err(_) => Err(format!("'{}' is not a port number", p)),
        },
    }
}

/// One connection and everything that belongs to it.
///
/// Split out of App so judytin can hold several at once. Scripting — aliases,
/// triggers, variables, classes — stays global, as it was: what is per-session
/// is the socket and the state that only makes sense beside a socket.
pub(crate) struct Session {
    /// What #session called it. Empty for the one judytin starts with, which
    /// nobody named.
    pub(crate) name: String,
    pub(crate) conn: Option<Conn>,
    /// Unique across every session ever opened, so a late packet from a
    /// connection that has already gone cannot be mistaken for a live one.
    pub(crate) conn_id: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) telnet: Telnet,
    pub(crate) line_buf: String,
    pub(crate) line_written: usize,
    /// How to get back here — see `Recipe`.
    pub(crate) recipe: Option<Recipe>,
    pub(crate) retry_at: Option<Instant>,
    pub(crate) retry_n: u32,
    pub(crate) settling: Option<Instant>,
    pub(crate) settle_cap: Option<Instant>,
    pub(crate) held: std::collections::VecDeque<String>,
}

impl Session {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            conn: None,
            conn_id: 0,
            host: String::new(),
            port: 0,
            telnet: Telnet::new(),
            line_buf: String::new(),
            line_written: 0,
            recipe: None,
            retry_at: None,
            retry_n: 0,
            settling: None,
            settle_cap: None,
            held: std::collections::VecDeque::new(),
        }
    }

    /// How it reads in a listing or a prefix.
    pub(crate) fn label(&self) -> &str {
        if self.name.is_empty() { "-" } else { &self.name }
    }
}

#[allow(clippy::large_enum_variant)] // single instance, always the Split arm in practice
pub enum Ui {
    Split(SplitUi),
    Dumb,
}

/// Control flow escaping from a command list.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flow {
    Ok,
    Break,
    Continue,
    Return,
}

pub struct Timed {
    pub body: String,
    pub interval: Duration,
    pub next: Instant,
    /// Set when the timer was created by server-driven execution, so its
    /// body inherits that restriction when it eventually fires rather than
    /// laundering it through the clock.
    pub server_driven: bool,
}

pub struct Trigger {
    pub body: String,
    /// remaining fires for oneshot/multishot triggers; None = unlimited
    pub shots: Option<u32>,
}

pub struct App {
    pub ui: Ui,
    pub quit: bool,
    pub(crate) tx: Sender<Ev>,
    pub(crate) aliases: BTreeMap<String, String>,
    pub(crate) actions: BTreeMap<String, Trigger>,
    pub(crate) highlights: BTreeMap<String, String>,
    pub(crate) subs: BTreeMap<String, String>,
    pub(crate) gags: BTreeSet<String>,
    pub(crate) vars: BTreeMap<String, String>,
    pub(crate) functions: BTreeMap<String, String>,
    pub(crate) macros: BTreeMap<String, String>,
    pub(crate) events: BTreeMap<String, String>,
    pub(crate) tabs: BTreeSet<String>,
    pub(crate) tickers: BTreeMap<String, Timed>,
    pub(crate) delays: BTreeMap<String, Timed>,
    pub(crate) delay_counter: u64,
    pub(crate) locals: Vec<BTreeMap<String, String>>,
    pub(crate) return_val: Option<String>,
    pub(crate) switch_stack: Vec<SwitchCtx>,
    pub(crate) current_class: Option<String>,
    pub(crate) class_index: BTreeMap<String, Vec<(String, String)>>,
    pub(crate) msg_off: BTreeSet<String>,
    pub(crate) quiet: u32,
    pub(crate) shots_mode: Option<u32>,
    pub(crate) gag_next: u32,
    pub(crate) speedwalk_on: bool,
    pub(crate) echo_on: bool,
    /// Nesting depth of server-caused execution (triggers, events). Above
    /// zero, commands that touch the machine are refused.
    pub(crate) server_driven: u32,
    /// Operator override: let server-driven triggers run shell and file
    /// commands anyway. Off by default, and saying yes is a real decision —
    /// it hands a hostile MUD the keys.
    pub(crate) trigger_shell: bool,
    pub(crate) verbatim_on: bool,
    pub(crate) repeat_char: char,
    pub(crate) packet_patch: Duration,
    pub(crate) log_file: Option<std::fs::File>,
    pub(crate) path: Vec<(String, String)>,
    pub(crate) path_pos: usize,
    pub(crate) path_mapping: bool,
    pub(crate) pathdirs: BTreeMap<String, String>,
    /// Every open session, in the order they were made. Never empty: judytin
    /// always has a current session even when it holds no connection, which is
    /// what `--offline` is.
    pub(crate) sessions: Vec<Session>,
    /// Index into `sessions` of the one that typing goes to.
    pub(crate) cur: usize,
    /// Rises with every connection across all sessions, never reused, so a
    /// packet from a session that has since closed cannot be delivered to
    /// whichever one happens to sit at the same index now.
    next_conn_id: u64,
    /// Set while judytin is handling a session other than the one the player
    /// is looking at, so its output can say where it came from.
    bg: Option<String>,
    /// Opt-in. Off by default because judytin cannot tell the server crashing
    /// from you typing the game's own quit command — both are just a socket
    /// closing — so arming this is a choice the player makes knowing that.
    pub(crate) reconnect_on: bool,
    /// Bytes not yet forming a whole UTF-8 character, held across packets.
    byte_buf: Vec<u8>,
    /// An escape sequence that arrived only partly, held until it finishes.
    esc_buf: String,
    flush_deadline: Option<Instant>,
}

pub struct SwitchCtx {
    pub value: crate::expr::Value,
    pub matched: bool,
}

fn default_pathdirs() -> BTreeMap<String, String> {
    let pairs = [
        ("n", "s"),
        ("e", "w"),
        ("u", "d"),
        ("north", "south"),
        ("east", "west"),
        ("up", "down"),
    ];
    let mut map = BTreeMap::new();
    for (a, b) in pairs {
        map.insert(a.to_string(), b.to_string());
        map.insert(b.to_string(), a.to_string());
    }
    map
}

impl App {
    pub fn new(ui: Ui, tx: Sender<Ev>) -> Self {
        App {
            ui,
            quit: false,
            tx,
            aliases: BTreeMap::new(),
            actions: BTreeMap::new(),
            highlights: BTreeMap::new(),
            subs: BTreeMap::new(),
            gags: BTreeSet::new(),
            vars: BTreeMap::new(),
            functions: BTreeMap::new(),
            macros: BTreeMap::new(),
            events: BTreeMap::new(),
            tabs: BTreeSet::new(),
            tickers: BTreeMap::new(),
            delays: BTreeMap::new(),
            delay_counter: 0,
            locals: Vec::new(),
            return_val: None,
            switch_stack: Vec::new(),
            current_class: None,
            class_index: BTreeMap::new(),
            msg_off: BTreeSet::new(),
            quiet: 0,
            shots_mode: None,
            gag_next: 0,
            speedwalk_on: false,
            echo_on: true,
            server_driven: 0,
            trigger_shell: false,
            verbatim_on: false,
            repeat_char: '!',
            packet_patch: Duration::from_millis(30),
            log_file: None,
            path: Vec::new(),
            path_pos: 0,
            path_mapping: false,
            pathdirs: default_pathdirs(),
            sessions: vec![Session::new("")],
            cur: 0,
            next_conn_id: 0,
            bg: None,
            reconnect_on: false,
            byte_buf: Vec::new(),
            esc_buf: String::new(),
            flush_deadline: None,
        }
    }

    // ---- output helpers -------------------------------------------------

    /// Raw output (already \r\n-terminated where needed).
    pub fn output(&mut self, raw: &str) {
        // Text from a session the player is not looking at says so. Losing it
        // would be worse, and showing it unmarked would be worse still: two
        // muds talking at once with nothing to tell them apart.
        if let Some(name) = self.bg.clone() {
            let tagged = raw
                .split_inclusive("\r\n")
                .map(|l| format!("\x1b[2m[{}]\x1b[0m {}", name, l))
                .collect::<String>();
            return self.write_out(&tagged);
        }
        self.write_out(raw);
    }

    fn write_out(&mut self, raw: &str) {
        if let Some(log) = &mut self.log_file {
            let (plain, _) = strip_map(raw);
            let _ = log.write_all(plain.replace('\r', "").as_bytes());
        }
        match &mut self.ui {
            Ui::Split(ui) => {
                let _ = ui.write_output(raw);
            }
            Ui::Dumb => {
                let mut out = std::io::stdout();
                let _ = out.write_all(raw.as_bytes());
                let _ = out.flush();
            }
        }
    }

    /// A local client message, shown dim with a leading '#'.
    pub fn info(&mut self, msg: &str) {
        if self.quiet > 0 {
            return;
        }
        self.output(&format!("\x1b[2m#{}\x1b[0m\r\n", msg));
    }

    /// Like info, but suppressible per trigger kind via #message.
    pub fn info_kind(&mut self, kind: &str, msg: &str) {
        if self.msg_off.contains(kind) || self.msg_off.contains("all") {
            return;
        }
        self.info(msg);
    }

    pub fn update_status(&mut self) {
        let state = match &self.s().conn {
            Some(c) if self.s().port > 0 => {
                format!("{}:{} ─ {}", self.s().host, self.s().port, c.kind())
            }
            Some(c) => format!("{} ─ {}", self.s().host, c.kind()),
            None => "offline".to_string(),
        };
        // With more than one session open, which one you are typing at is the
        // single most important thing the bar can tell you.
        let text = if self.sessions.len() > 1 {
            format!(
                "judytin ─ {} ─ {} of {}",
                state,
                self.s().label(),
                self.sessions.len()
            )
        } else {
            format!("judytin ─ {}", state)
        };
        if let Ui::Split(ui) = &mut self.ui {
            let _ = ui.set_status(&text);
        }
    }

    // ---- variables & substitution ---------------------------------------

    pub fn get_var(&self, name: &str) -> Option<String> {
        // $inv[-1] and $inv[+1] are positions in a list, not names. Rewriting
        // here rather than in the substituter keeps it in one place and keeps
        // it out of the parser, where a subscript is still just text.
        let resolved = crate::list::resolve_name(&self.vars, name);
        let name = resolved.as_deref().unwrap_or(name);
        for scope in self.locals.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Some(v.clone());
            }
        }
        if let Some(v) = self.vars.get(name) {
            return Some(v.clone());
        }
        // `$session` is where this is running, not something anyone set.
        //
        // A trigger fires in the focus of the session whose line set it off,
        // and until now it had no way to ask which one that was — so three
        // characters logging in needed three near-identical triggers instead
        // of one. Last, so a variable the player did define still wins and no
        // existing script changes meaning.
        (name == "session").then(|| self.s().name.clone())
    }

    /// Update the innermost scope that has the name, else set globally.
    pub fn set_var(&mut self, name: &str, value: &str) {
        for scope in self.locals.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), value.to_string());
                return;
            }
        }
        self.vars.insert(name.to_string(), value.to_string());
    }

    pub fn set_local(&mut self, name: &str, value: &str) {
        if let Some(scope) = self.locals.last_mut() {
            scope.insert(name.to_string(), value.to_string());
        } else {
            self.vars.insert(name.to_string(), value.to_string());
        }
    }

    /// Variable then @function substitution — the tt++ "when used" pass.
    pub fn subst(&mut self, text: &str, depth: u32) -> String {
        let with_vars = {
            let me: &App = self;
            script::subst_vars_with(text, &|name| me.get_var(name))
        };
        self.subst_functions(&with_vars, depth)
    }

    fn subst_functions(&mut self, text: &str, depth: u32) -> String {
        if !text.contains('@') || depth > MAX_DEPTH {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'@' {
                let ch_end = next_char(text, i);
                out.push_str(&text[i..ch_end]);
                i = ch_end;
                continue;
            }
            if bytes.get(i + 1) == Some(&b'@') {
                out.push('@');
                i += 2;
                continue;
            }
            // @name{args}
            let name_start = i + 1;
            let mut j = name_start;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
            {
                j += 1;
            }
            let name = &text[name_start..j];
            if name.is_empty()
                || bytes.get(j) != Some(&b'{')
                || !self.functions.contains_key(name)
            {
                out.push('@');
                i += 1;
                continue;
            }
            // find matching brace
            let mut depth_b = 0usize;
            let mut k = j;
            let mut end = None;
            while k < bytes.len() {
                match bytes[k] {
                    b'{' => depth_b += 1,
                    b'}' => {
                        depth_b -= 1;
                        if depth_b == 0 {
                            end = Some(k);
                            break;
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
            let Some(end) = end else {
                out.push('@');
                i += 1;
                continue;
            };
            let args_raw = &text[j + 1..end];
            let name = name.to_string();
            let args_raw = args_raw.to_string();
            let result = self.call_function(&name, &args_raw, depth + 1);
            out.push_str(&result);
            i = end + 1;
        }
        out
    }

    pub fn call_function(&mut self, name: &str, args_raw: &str, depth: u32) -> String {
        let Some(body) = self.functions.get(name).cloned() else {
            return String::new();
        };
        let args = self.subst(args_raw, depth);
        // Split on unescaped separators only: an escaped `;` inside an
        // argument is data and must not become an argument boundary.
        let mut caps: Vec<(u8, String)> = script::split_unescaped(&args, ';')
            .into_iter()
            .filter(|a| !a.is_empty())
            .enumerate()
            .take(99)
            .map(|(i, a)| ((i + 1) as u8, a))
            .collect();
        caps.push((0, args.clone()));
        // The function body is user-authored but the arguments may carry
        // server data, and the result is parsed again — so the arguments
        // keep whatever escaping they arrived with.
        let expanded = pattern::expand(&body, &caps, &args);
        let saved_ret = self.return_val.take();
        self.locals.push(BTreeMap::new());
        let _ = self.run_input(&expanded, depth + 1);
        let scope = self.locals.pop().unwrap_or_default();
        let result = self
            .return_val
            .take()
            .or_else(|| scope.get("result").cloned())
            .or_else(|| self.vars.get("result").cloned())
            .unwrap_or_default();
        self.return_val = saved_ret;
        result
    }

    /// Run a stored trigger/alias/timer body: %-expansion done by caller;
    /// gets its own local scope, and loop-control flow stops here.
    pub fn run_body(&mut self, body: &str, depth: u32) {
        self.locals.push(BTreeMap::new());
        let _ = self.run_input(body, depth);
        self.locals.pop();
    }

    /// Run a body that the server caused to run — a trigger or an event.
    ///
    /// The second layer of defence. Escaping (see [`crate::data`]) already
    /// stops server text from becoming commands; this marks the execution
    /// itself so that commands with effects outside the game — shell,
    /// subprocess, filesystem — refuse to run, however they were reached.
    /// If a parser bug ever lets data escape, the blast radius is the MUD
    /// session, not the machine.
    pub fn run_server_body(&mut self, body: &str, depth: u32) {
        self.server_driven += 1;
        self.run_body(body, depth);
        self.server_driven -= 1;
    }

    /// May a command with effects outside the game run right now?
    pub fn local_effects_allowed(&self) -> bool {
        self.server_driven == 0 || self.trigger_shell
    }

    // ---- networking -----------------------------------------------------

    pub fn connect(&mut self, host: &str, port: u16) {
        if self.s().conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("trying {}:{} ...", host, port));
        self.next_conn_id += 1;
        let id = self.next_conn_id;
        self.s_mut().conn_id = id;
        match net::connect_tcp(host, port, id, self.tx.clone()) {
            Ok(conn) => self.finish_connect(
                conn,
                host,
                port,
                Recipe::Tcp { host: host.to_string(), port },
            ),
            Err(e) => self.info(&format!("connection to {}:{} failed: {}", host, port, e)),
        }
    }

    pub fn connect_tls(&mut self, host: &str, port: u16) {
        if self.s().conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("trying {}:{} (tls) ...", host, port));
        self.next_conn_id += 1;
        let id = self.next_conn_id;
        self.s_mut().conn_id = id;
        match net::connect_tls(host, port, id, self.tx.clone()) {
            Ok((conn, pin)) => {
                match pin {
                    Pin::New(fp) => {
                        self.info(&format!("first connection — pinned server cert {}", fp));
                        self.info("(stored in ~/.judytin_known_hosts)");
                    }
                    Pin::Known => self.info("server certificate matches the pinned one"),
                }
                self.finish_connect(
                    conn,
                    host,
                    port,
                    Recipe::Tls { host: host.to_string(), port },
                );
            }
            Err(e) => self.info(&format!("tls connection to {}:{} failed: {}", host, port, e)),
        }
    }

    /// Connect through the system ssh. Separate from `connect_pipe` because
    /// judytin built this command line itself and so can read the child's
    /// stderr as ssh's, which a bare `#run` cannot.
    pub fn connect_ssh(&mut self, dest: &str) {
        let command = net::ssh_command(dest);
        self.start_pipe(dest, &command, Some(dest));
    }

    pub fn connect_pipe(&mut self, label: &str, command: &str) {
        self.start_pipe(label, command, None);
    }

    /// Open whatever the recipe says. The one place that knows how each
    /// transport is started, so `#session`, `#ssl`, `#run` and the automatic
    /// retry all agree about what a recipe means.
    pub(crate) fn start(&mut self, how: Recipe) {
        match how {
            Recipe::Tcp { host, port } => self.connect(&host, port),
            Recipe::Tls { host, port } => self.connect_tls(&host, port),
            Recipe::Pipe { label, command, ssh } => {
                self.start_pipe(&label, &command, ssh.as_deref())
            }
        }
    }

    fn start_pipe(&mut self, label: &str, command: &str, ssh_dest: Option<&str>) {
        if self.s().conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("running {} ...", command));
        self.next_conn_id += 1;
        let id = self.next_conn_id;
        self.s_mut().conn_id = id;
        match net::connect_pipe(command, ssh_dest, id, self.tx.clone()) {
            Ok(conn) => self.finish_connect(
                conn,
                label,
                0,
                Recipe::Pipe {
                    label: label.to_string(),
                    command: command.to_string(),
                    ssh: ssh_dest.map(str::to_string),
                },
            ),
            Err(e) => self.info(&format!("cannot run '{}': {}", command, e)),
        }
    }

    fn finish_connect(&mut self, conn: Conn, host: &str, port: u16, how: Recipe) {
        let kind = conn.kind();
        self.s_mut().conn = Some(conn);
        // Remember how we got here before anything can go wrong with it, and
        // treat arriving as proof the backoff has done its job.
        self.s_mut().recipe = Some(how);
        self.s_mut().retry_at = None;
        self.s_mut().retry_n = 0;
        // A connection that has not spoken yet may still be negotiating. Hold
        // player text until it has, so the first thing judytin says is not sent
        // over the top of the first thing it was told.
        let cap = Instant::now() + Self::SETTLE;
        self.s_mut().settling = Some(cap);
        self.s_mut().settle_cap = Some(cap);
        self.s_mut().held.clear();
        self.s_mut().host = host.to_string();
        self.s_mut().port = port;
        self.s_mut().telnet = Telnet::new();
        self.s_mut().line_buf.clear();
        self.s_mut().line_written = 0;
        if port > 0 {
            self.info(&format!("connected to {}:{} ({})", host, port, kind));
        } else {
            self.info(&format!("connected ({})", kind));
        }
        self.update_status();
        self.fire_event(
            "SESSION CONNECTED",
            &[
                "judytin".to_string(),
                host.to_string(),
                host.to_string(),
                port.to_string(),
            ],
        );
    }

    /// Where `name` sits in `sessions`, if it is open at all.
    ///
    /// Exact first, then ignoring case: a name is the player's own word, and
    /// `#Bob` should reach the session they called `bob` rather than inventing
    /// a second one — but an exact match is never overruled by a sloppy one.
    pub(crate) fn session_index(&self, name: &str) -> Option<usize> {
        self.sessions
            .iter()
            .position(|x| x.name == name)
            .or_else(|| self.sessions.iter().position(|x| x.name.eq_ignore_ascii_case(name)))
            // The session nobody named reads as `-` in the listing, so `-` is
            // what someone will type to reach it. Last, so a session actually
            // called `-` is still itself.
            .or_else(|| self.sessions.iter().position(|x| x.label() == name))
    }

    /// Make `name` the session that typing goes to, creating nothing.
    /// Returns false if there is no such session.
    pub(crate) fn switch_to(&mut self, name: &str) -> bool {
        match self.session_index(name) {
            Some(i) => {
                self.cur = i;
                self.update_status();
                true
            }
            None => false,
        }
    }

    /// Get a session ready to connect under `name`, and focus it.
    ///
    /// Reuses the current one when it is the unnamed starting session and
    /// idle, so `judytin --offline` followed by `#session {mud} …` gives one
    /// session rather than a named one beside a leftover blank.
    pub(crate) fn open_session(&mut self, name: &str) -> bool {
        if let Some(i) = self.sessions.iter().position(|x| x.name == name) {
            if self.sessions[i].conn.is_some() {
                let msg = format!("session {} is already connected — #zap it first", name);
                self.info(&msg);
                return false;
            }
            self.cur = i;
            return true;
        }
        // Commands win over session names, so a session called after one
        // cannot be reached by `#name`. Said now, while the name is still the
        // player's to change, rather than left to be discovered.
        if crate::commands::is_command_name(name) {
            let msg = format!(
                "note: #{} is already a command, so this session answers to \
                 #session {{{}}} rather than #{}",
                name, name, name
            );
            self.info(&msg);
        }
        if self.s().name.is_empty() && self.s().conn.is_none() {
            self.s_mut().name = name.to_string();
            return true;
        }
        self.sessions.push(Session::new(name));
        self.cur = self.sessions.len() - 1;
        true
    }

    /// Close the current session and hand the focus to another if there is
    /// one.
    ///
    /// The last session is disconnected but kept, name and recipe intact, so
    /// `#zap` followed by `#reconnect` still works — which is what it did
    /// before judytin could hold more than one session, and there is no reason
    /// for that to change just because the count can now exceed one.
    pub(crate) fn close_session(&mut self) {
        self.close_session_at(self.cur);
    }

    /// Close session `i`, which need not be the one being watched.
    ///
    /// The disconnect happens in that session's own focus, so its parting
    /// words are tagged with its name and its events fire where they belong;
    /// the focus then goes back to whichever session the player was actually
    /// looking at, found by name because removing an element moves the ones
    /// after it.
    pub(crate) fn close_session_at(&mut self, i: usize) {
        let gone = self.sessions[i].label().to_string();
        self.on_session(i, |a| a.disconnect(false));
        if self.sessions.len() > 1 {
            let watching = self.sessions[self.cur].name.clone();
            self.sessions.remove(i);
            self.cur = self
                .session_index(&watching)
                .unwrap_or_else(|| self.cur.min(self.sessions.len() - 1));
            let now = self.s().label().to_string();
            self.info(&format!("closed {} — now on {}", gone, now));
        }
        self.update_status();
    }

    /// The session typing goes to. Always exists — see `sessions`.
    pub(crate) fn s(&self) -> &Session {
        &self.sessions[self.cur]
    }

    pub(crate) fn s_mut(&mut self) -> &mut Session {
        &mut self.sessions[self.cur]
    }

    /// Find a session by the id its connection was opened with. Returns the
    /// index so the caller can tell whether it is the current one, which is
    /// what decides whether its output gets a name in front of it.
    fn session_of(&self, conn_id: u64) -> Option<usize> {
        self.sessions.iter().position(|x| x.conn_id == conn_id)
    }

    /// How long to wait before attempt `n`. Grows to half a minute and stays
    /// there — a server being rebuilt can be gone for a while, and hammering
    /// it helps nobody.
    fn backoff(n: u32) -> Duration {
        Duration::from_secs(match n {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            4 => 16,
            _ => 30,
        })
    }

    /// Schedule another attempt after a drop judytin did not ask for.
    ///
    /// Never gives up: the retry is what the player armed, and stopping after
    /// some arbitrary count would abandon them at the moment a long rebuild
    /// finishes. `#zap` ends it, and every attempt says so.
    pub(crate) fn arm_reconnect(&mut self) {
        if !self.reconnect_on || self.s().recipe.is_none() {
            return;
        }
        let wait = Self::backoff(self.s().retry_n);
        self.s_mut().retry_at = Some(Instant::now() + wait);
        self.info(&format!(
            "reconnecting in {}s — #zap to stop",
            wait.as_secs()
        ));
    }

    /// Throw away queued text when the connection it was meant for is gone.
    /// Sending it to whatever comes next would put the player's words in a
    /// place they never chose.
    pub(crate) fn drop_held(&mut self) {
        self.s_mut().settling = None;
        self.s_mut().settle_cap = None;
        let n = self.s().held.len();
        self.s_mut().held.clear();
        if n > 0 {
            self.info(&format!(
                "{} unsent line{} dropped with the connection",
                n,
                if n == 1 { "" } else { "s" }
            ));
        }
    }

    pub(crate) fn cancel_reconnect(&mut self) {
        self.s_mut().retry_at = None;
        self.s_mut().retry_n = 0;
    }

    /// Try the stored recipe once. `manual` is #reconnect, which runs whatever
    /// the config says and does not schedule a follow-up; the automatic path
    /// arms the next attempt when this one does not take.
    pub(crate) fn reconnect(&mut self, manual: bool) {
        let Some(how) = self.s().recipe.clone() else {
            self.info("no session to return to — #session, #ssl or #run first");
            return;
        };
        if self.s().conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.s_mut().retry_at = None;
        if !manual {
            self.s_mut().retry_n = self.s_mut().retry_n.saturating_add(1);
        }
        self.start(how);
        if self.s().conn.is_none() && !manual {
            self.arm_reconnect();
        }
    }

    pub fn disconnect(&mut self, quiet: bool) {
        // The player asked to leave. Whatever retry was pending is no longer
        // wanted, and this is the only signal judytin gets that says so.
        self.cancel_reconnect();
        self.drop_held();
        if let Some(mut conn) = self.s_mut().conn.take() {
            conn.shutdown();
            if !quiet {
                self.info("connection closed (zap)");
            }
            let (host, port) = (self.s().host.clone(), self.s().port.to_string());
            self.fire_event(
                "SESSION DISCONNECTED",
                &["judytin".to_string(), host.clone(), host, port],
            );
        } else if !quiet {
            self.info("not connected");
        }
        self.update_status();
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        if let Some(conn) = &mut self.s_mut().conn
            && conn.send(bytes).is_err()
        {
            self.info("send failed — connection lost");
            self.disconnect(true);
            // disconnect() clears the retry because it is normally the player
            // leaving; here the connection left, so put it back.
            self.arm_reconnect();
        }
    }

    /// How long a new connection gets to say something before judytin gives up
    /// waiting and sends anyway. Only a backstop: a server that greets you —
    /// which is nearly all of them — releases the hold in milliseconds.
    const SETTLE: Duration = Duration::from_secs(2);

    /// How long the server must stay quiet before its opening counts as over.
    /// A greeting is written back to back but need not arrive in one packet:
    /// releasing on the first byte can land between a banner and the option
    /// negotiation behind it, which is the whole thing being avoided.
    const QUIET: Duration = Duration::from_millis(250);

    /// Stop holding player text, and send whatever piled up, in order.
    fn release_held(&mut self) {
        self.s_mut().settling = None;
        self.s_mut().settle_cap = None;
        while let Some(line) = self.s_mut().held.pop_front() {
            self.send_now(&line);
        }
    }

    /// Send one line to the MUD. A sink: escaped data becomes plain text
    /// here, on its way out of the client's grammar for good.
    pub fn send_line(&mut self, line: &str) {
        let line = &crate::data::unescape(line);
        if self.s().conn.is_none() {
            self.info(&format!("not connected — cannot send '{}'. try #session", line));
            return;
        }
        // A connection that has not spoken yet may be mid-negotiation, and with
        // input arriving from a pipe judytin can otherwise flush a whole login
        // dialogue before the first prompt lands. Queue instead; the server's
        // first byte, or SETTLE, lets it go. Telnet replies do not come through
        // here, so an option is still answered the instant it is offered.
        if self.s().settling.is_some() {
            self.s_mut().held.push_back(line.to_string());
            return;
        }
        self.send_now(line);
    }

    fn send_now(&mut self, line: &str) {
        if self.path_mapping
            && let Some(rev) = self.pathdirs.get(line).cloned()
        {
            self.path.push((line.to_string(), rev));
            self.path_pos = self.path.len();
        }
        let mut data = line.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        self.send_raw(&data);
    }

    // ---- events ---------------------------------------------------------

    pub fn fire_event(&mut self, name: &str, args: &[String]) {
        let Some(body) = self.events.get(name).cloned() else {
            return;
        };
        let caps: Vec<(u8, String)> = args
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u8, a.clone()))
            .collect();
        let all = args.first().cloned().unwrap_or_default();
        // Event arguments are raw server text (RECEIVED LINE hands over the
        // whole line), so they cross the same boundary as trigger captures.
        let expanded = pattern::expand_data(&body, &caps, &all);
        self.run_server_body(&expanded, 1);
    }

    // ---- event dispatch -------------------------------------------------

    pub fn on_event(&mut self, ev: Ev) {
        match ev {
            Ev::Key(key) => self.on_key(key),
            Ev::Resize(c, r) => {
                if let Ui::Split(ui) = &mut self.ui {
                    let _ = ui.resize(c, r);
                }
            }
            Ev::Line(line) => self.handle_user_line(&line),
            Ev::StdinEof => {
                if self.s().conn.is_none() {
                    self.quit = true;
                } else {
                    // Staying is deliberate — it is how `printf 'look\n' |
                    // judytin --dumb` watches what comes back. But saying
                    // nothing turns a script that forgot `quit` into a
                    // pipeline that hangs with no explanation anywhere.
                    self.info(
                        "input ended, still connected — watching the mud. \
                         Send #end in the script, or interrupt, to stop.",
                    );
                }
            }
            Ev::Net(id, bytes) => {
                if let Some(i) = self.session_of(id) {
                    self.on_session(i, |a| a.on_net_data(&bytes));
                }
            }
            Ev::NetDiag(id, note) => {
                if let Some(i) = self.session_of(id) {
                    self.on_session(i, |a| a.info(&note));
                }
            }
            Ev::NetClosed(id, why) => {
                if let Some(i) = self.session_of(id) {
                    self.on_session(i, |a| a.on_net_closed(&why));
                }
            }
        }
    }

    /// Handle something that happened to session `i`.
    ///
    /// The whole pipeline below — telnet, line assembly, triggers, output —
    /// reads and writes "the current session". Threading an index through all
    /// of it would touch every layer for no gain, so the focus moves instead.
    /// That is also the right answer for triggers: one firing on a background
    /// line replies to the session that produced the line, not to whichever
    /// the player happens to be watching.
    pub(crate) fn on_session<R>(&mut self, i: usize, f: impl FnOnce(&mut Self) -> R) -> R {
        let back_to = self.s().name.clone();
        let watching = self.cur;
        self.cur = i;
        self.bg = (i != watching).then(|| self.sessions[i].label().to_string());
        let out = f(self);
        self.bg = None;
        // A #session inside a trigger is the player's own choice and outranks
        // putting the focus back; only restore if nothing moved it.
        if self.cur == i
            && let Some(j) = self.sessions.iter().position(|x| x.name == back_to)
        {
            self.cur = j;
        }
        out
    }

    fn on_net_closed(&mut self, why: &str) {
        if self.s().conn.is_some() {
            self.s_mut().conn = None;
            self.drop_held();
            self.flush_partial();
            if !self.s().line_buf.is_empty() {
                self.output("\r\n");
                self.s_mut().line_buf.clear();
                self.s_mut().line_written = 0;
            }
            self.info(why);
            self.update_status();
            let (host, port) = (self.s().host.clone(), self.s().port.to_string());
            self.fire_event(
                "SESSION DISCONNECTED",
                &["judytin".to_string(), host.clone(), host, port],
            );
            // The socket went away without judytin asking. This is the
            // case worth chasing — and the one judytin cannot tell from
            // the player typing the game's own quit, so it only chases
            // when asked to.
            self.arm_reconnect();
            // A piped run ends when there is nothing left to wait for: no
            // session still connected, and none expecting to be. Asking only
            // about the session that just closed was right when judytin held
            // one, and wrong the moment it could hold four — the first socket
            // to go would take the live ones with it.
            let waiting = self
                .sessions
                .iter()
                .any(|x| x.conn.is_some() || x.retry_at.is_some());
            if matches!(self.ui, Ui::Dumb) && !waiting {
                self.quit = true;
            }
        }
    }

    fn on_key(&mut self, key: crossterm::event::KeyEvent) {
        // macros first
        if let Some(name) = macro_key_name(&key)
            && let Some(body) = self.macros.get(&name).cloned()
        {
            self.run_body(&body, 1);
            return;
        }
        let result = if let Ui::Split(ui) = &mut self.ui {
            ui.handle_key(key).unwrap_or(crate::ui::InputResult::None)
        } else {
            crate::ui::InputResult::None
        };
        match result {
            crate::ui::InputResult::Submit(line) => self.handle_user_line(&line),
            crate::ui::InputResult::Tab => self.tab_complete(),
            crate::ui::InputResult::Quit => self.quit = true,
            crate::ui::InputResult::None => {}
        }
    }

    fn tab_complete(&mut self) {
        let Ui::Split(ui) = &mut self.ui else { return };
        let word = ui.current_word().to_string();
        if word.is_empty() {
            return;
        }
        let mut candidates: BTreeSet<String> = self
            .tabs
            .iter()
            .filter(|t| t.starts_with(&word) && t.as_str() != word)
            .cloned()
            .collect();
        // words from recent output
        for line in ui.buffer_lines().rev().take(200) {
            let (plain, _) = strip_map(line);
            for w in plain.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-')) {
                if w.len() > 2 && w.starts_with(&word) && w != word {
                    candidates.insert(w.to_string());
                }
            }
        }
        if candidates.is_empty() {
            return;
        }
        // longest common prefix of all candidates
        let mut prefix = candidates.iter().next().unwrap().clone();
        for c in &candidates {
            while !c.starts_with(&prefix) {
                prefix.pop();
            }
        }
        let completion = if candidates.len() == 1 || prefix.len() > word.len() {
            prefix
        } else {
            candidates.iter().next().unwrap().clone()
        };
        let _ = ui.complete_word(&completion);
    }

    // ---- timers ---------------------------------------------------------

    pub fn next_deadline(&self) -> Option<Instant> {
        let tick = self.tickers.values().map(|t| t.next).min();
        let delay = self.delays.values().map(|t| t.next).min();
        // Every session's clocks, not just the one being watched: a background
        // session's retry is exactly the thing that must go off unattended.
        let sessions = self
            .sessions
            .iter()
            .flat_map(|x| [x.retry_at, x.settling])
            .flatten()
            .min();
        [tick, delay, self.flush_deadline, sessions]
            .into_iter()
            .flatten()
            .min()
    }

    /// Run everything whose time has come: tickers, delays, pending
    /// partial-line display. Called by the main loop after each event.
    pub fn tick(&mut self) {
        if let Some(d) = self.flush_deadline
            && d <= Instant::now()
        {
            self.flush_partial();
        }
        let now = Instant::now();
        // Each session's own clocks, run in its own focus so a retry reconnects
        // the session it belongs to rather than the one being watched.
        for i in 0..self.sessions.len() {
            if self.sessions[i].settling.is_some_and(|d| d <= now) {
                // Either the greeting is over or the server never had one.
                // Waiting further would look like judytin ignoring what was
                // typed, which is worse than sending it a moment late.
                self.on_session(i, |a| a.release_held());
            }
            if self.sessions[i].retry_at.is_some_and(|d| d <= now) {
                self.on_session(i, |a| a.reconnect(false));
            }
        }
        let now = Instant::now();
        let due: Vec<(String, String, bool)> = self
            .tickers
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, t)| (k.clone(), t.body.clone(), t.server_driven))
            .collect();
        for (name, body, from_server) in due {
            if let Some(t) = self.tickers.get_mut(&name) {
                while t.next <= now {
                    t.next += t.interval;
                }
            }
            if from_server {
                self.run_server_body(&body, 1);
            } else {
                self.run_body(&body, 1);
            }
        }
        let due: Vec<String> = self
            .delays
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for name in due {
            if let Some(t) = self.delays.remove(&name) {
                if t.server_driven {
                    self.run_server_body(&t.body, 1);
                } else {
                    self.run_body(&t.body, 1);
                }
            }
        }
    }

    // ---- server output pipeline ----------------------------------------

    fn on_net_data(&mut self, bytes: &[u8]) {
        let (data, reply) = self.s_mut().telnet.feed(bytes);
        if !reply.is_empty() {
            self.send_raw(&reply);
        }
        // The server is still opening. Wait for it to pause rather than taking
        // the first packet as the whole greeting.
        if self.s().settling.is_some() {
            let next = Instant::now() + Self::QUIET;
            self.s_mut().settling = match self.s_mut().settle_cap {
                Some(cap) if cap < next => Some(cap),
                _ => Some(next),
            };
        }
        let masked = self.s().telnet.server_echo;
        if let Ui::Split(ui) = &mut self.ui {
            ui.masked = masked;
        }
        // Decode across packet boundaries, not per packet: a multi-byte
        // character split by TCP would otherwise arrive as two replacement
        // characters.
        self.byte_buf.extend_from_slice(&data);
        let text = match std::str::from_utf8(&self.byte_buf) {
            Ok(text) => {
                let text = text.to_string();
                self.byte_buf.clear();
                text
            }
            Err(error) => {
                let good = error.valid_up_to();
                let text = String::from_utf8_lossy(&self.byte_buf[..good]).into_owned();
                // Keep only a genuine partial tail; anything longer is
                // malformed and would grow without bound.
                let tail = self.byte_buf.split_off(good);
                self.byte_buf = if tail.len() <= 4 { tail } else { Vec::new() };
                text
            }
        };
        // Filter before anything downstream sees it: the terminal is an
        // interpreter too, and only colour belongs to the server. An escape
        // sequence split across packets is rejoined here rather than being
        // half-filtered — with a cap, so a sequence that never ends cannot
        // become a second unbounded buffer.
        let text = if self.esc_buf.is_empty() {
            text
        } else {
            format!("{}{}", std::mem::take(&mut self.esc_buf), text)
        };
        let (text, incomplete) = crate::ansi::sanitize(&text);
        self.esc_buf = if incomplete.len() <= 256 {
            incomplete
        } else {
            String::new()
        };
        for c in text.chars() {
            match c {
                '\n' => self.complete_line(),
                '\r' => {}
                _ => {
                    self.s_mut().line_buf.push(c);
                    // A server that never sends a newline must not be able
                    // to grow this without limit, nor hand the pattern
                    // matcher a line long enough to freeze the client.
                    if self.s().line_buf.len() >= MAX_LINE {
                        self.complete_line();
                    }
                }
            }
        }
        // Unterminated tail (usually the prompt): hold it briefly so a reply
        // that continues the line still gets full trigger processing, then
        // display it via tick().
        self.flush_deadline = if self.s().line_buf.len() > self.s().line_written {
            Some(Instant::now() + self.packet_patch)
        } else {
            None
        };
    }

    /// Display any not-yet-shown part of the current unterminated line
    /// (usually the prompt). Shown raw; triggers run on line completion.
    fn flush_partial(&mut self) {
        self.flush_deadline = None;
        if self.s().line_buf.len() > self.s().line_written {
            let frag = self.s().line_buf[self.s().line_written..].to_string();
            self.s_mut().line_written = self.s_mut().line_buf.len();
            self.output(&frag);
            let full = self.s().line_buf.clone();
            let (plain, _) = strip_map(&full);
            self.fire_event("RECEIVED PROMPT", &[full, plain]);
        }
    }

    fn complete_line(&mut self) {
        let raw = std::mem::take(&mut self.s_mut().line_buf);
        let written = std::mem::take(&mut self.s_mut().line_written);
        let (plain, _) = strip_map(&raw);

        // Collect matching action bodies (and count down multishots).
        // expand_data, not expand: these captures are server text, and this
        // is the boundary where they must stop being able to become code.
        let mut to_run: Vec<String> = Vec::new();
        let mut spent: Vec<String> = Vec::new();
        for (pat, trig) in &self.actions {
            if let Some(caps) = pattern::matches(pat, &plain) {
                to_run.push(pattern::expand_data(&trig.body, &caps, &plain));
                if trig.shots.is_some() {
                    spent.push(pat.clone());
                }
            }
        }
        for pat in spent {
            if let Some(t) = self.actions.get_mut(&pat) {
                let left = t.shots.unwrap_or(1).saturating_sub(1);
                if left == 0 {
                    self.actions.remove(&pat);
                } else {
                    t.shots = Some(left);
                }
            }
        }

        let mut gagged = self.gags.iter().any(|g| pattern::matches(g, &plain).is_some());
        if self.gag_next > 0 {
            self.gag_next -= 1;
            gagged = true;
        }
        if written > 0 {
            // The line was partially shown already (a parked prompt the
            // server then continued). In split mode, patch it tt++-style:
            // erase the partial and rewrite the whole processed line. In
            // dumb mode (a pipe), just append the raw remainder.
            if matches!(self.ui, Ui::Split(_)) {
                if gagged {
                    self.output("\r\x1b[2K");
                } else {
                    let processed = self.apply_subs_and_highlights(raw.clone());
                    self.output(&format!("\r\x1b[2K{}\r\n", processed));
                }
            } else {
                let rest = raw[written..].to_string();
                self.output(&format!("{}\r\n", rest));
            }
        } else if !gagged {
            let processed = self.apply_subs_and_highlights(raw.clone());
            self.output(&format!("{}\r\n", processed));
        }

        for body in to_run {
            self.run_server_body(&body, 1);
        }
        self.fire_event("RECEIVED LINE", &[raw, plain]);
    }

    fn apply_subs_and_highlights(&self, mut raw: String) -> String {
        for (pat, repl) in &self.subs {
            let compiled = pattern::compile(pat);
            let mut guard = 0;
            let mut search_from = 0usize; // plain byte offset to resume from
            loop {
                guard += 1;
                if guard > 20 {
                    break;
                }
                let (plain, map) = strip_map(&raw);
                search_from = ceil_boundary(&plain, search_from);
                if search_from >= plain.len() {
                    break;
                }
                match pattern::find(&compiled, &plain[search_from..]) {
                    Some((a, b, caps)) => {
                        let (a, b) = (search_from + a, search_from + b);
                        let matched = &plain[a..b];
                        let replacement = pattern::expand(repl, &caps, matched);
                        let mut next = String::with_capacity(raw.len());
                        next.push_str(&raw[..map[a]]);
                        next.push_str(&replacement);
                        next.push_str(&raw[map[b]..]);
                        // continue after the replacement (avoids loops when
                        // the replacement re-contains the pattern)
                        search_from = a + replacement.len();
                        raw = next;
                        if a == b && replacement.is_empty() {
                            search_from += 1;
                        }
                    }
                    None => break,
                }
            }
        }
        for (pat, color) in &self.highlights {
            let Some(code) = crate::ansi::color_code(color) else { continue };
            let compiled = pattern::compile(pat);
            let mut guard = 0;
            let mut search_from = 0usize;
            loop {
                guard += 1;
                if guard > 20 {
                    break;
                }
                let (plain, map) = strip_map(&raw);
                search_from = ceil_boundary(&plain, search_from);
                if search_from >= plain.len() {
                    break;
                }
                match pattern::find(&compiled, &plain[search_from..]) {
                    Some((a, b, _)) if b > a => {
                        let (a, b) = (search_from + a, search_from + b);
                        let mut next = String::with_capacity(raw.len() + 12);
                        next.push_str(&raw[..map[a]]);
                        next.push_str(&code);
                        next.push_str(&raw[map[a]..map[b]]);
                        next.push_str(crate::ansi::RESET);
                        next.push_str(&raw[map[b]..]);
                        search_from = b + 1;
                        raw = next;
                    }
                    _ => break,
                }
            }
        }
        raw
    }

    // ---- input pipeline -------------------------------------------------

    pub fn handle_user_line(&mut self, line: &str) {
        // history recall: !! last, !text prefix search, !N by number
        let line_owned;
        let mut line = line;
        if line.starts_with(self.repeat_char) && line.len() > 1 {
            match self.recall_history(&line[self.repeat_char.len_utf8()..]) {
                Some(hit) => {
                    line_owned = hit;
                    line = &line_owned;
                }
                None => {
                    self.info("no matching history entry");
                    return;
                }
            }
        }
        self.flush_partial();
        if self.echo_on && matches!(self.ui, Ui::Split(_)) && !self.s().telnet.server_echo {
            // the echo lands right after any dangling prompt, closing its line
            self.output(&format!("\x1b[2m{}\x1b[0m\r\n", line));
            self.s_mut().line_buf.clear();
            self.s_mut().line_written = 0;
        }
        if matches!(self.ui, Ui::Dumb) && !self.s().telnet.server_echo {
            // Not while the server has taken ECHO: that is a password
            // prompt, and this echo would put it on screen and in the log.
            let mut msg = String::from("\x1b[2m>> ");
            msg.push_str(line);
            msg.push_str("\x1b[0m\r\n");
            self.output(&msg);
        }
        if line.is_empty() {
            self.send_line("");
            return;
        }
        if self.verbatim_on && !line.starts_with('#') {
            let text = line.to_string();
            self.send_line(&text);
            return;
        }
        let _ = self.run_input(line, 0);
    }

    fn recall_history(&mut self, spec: &str) -> Option<String> {
        let Ui::Split(ui) = &self.ui else { return None };
        let hist = ui.history();
        if spec == "!" {
            return hist.last().cloned();
        }
        if let Ok(n) = spec.parse::<usize>() {
            return hist.get(n.checked_sub(1)?).cloned();
        }
        hist.iter().rev().find(|h| h.starts_with(spec)).cloned()
    }

    pub fn run_input(&mut self, input: &str, depth: u32) -> Flow {
        if depth > MAX_DEPTH {
            self.info("recursion depth exceeded — check your aliases/actions");
            return Flow::Ok;
        }
        let mut chain: Option<bool> = None;
        for cmd in script::split_commands(input) {
            let flow = self.exec_one(&cmd, depth, &mut chain);
            if flow != Flow::Ok {
                return flow;
            }
        }
        Flow::Ok
    }

    fn exec_one(&mut self, cmd: &str, depth: u32, chain: &mut Option<bool>) -> Flow {
        if let Some(rest) = cmd.strip_prefix('#') {
            return self.tintin_command(rest.trim(), depth, chain);
        }
        *chain = None;
        // alias expansion on the first word
        let (head, tail) = match cmd.find(char::is_whitespace) {
            Some(i) => (&cmd[..i], cmd[i..].trim_start()),
            None => (cmd, ""),
        };
        if let Some(body) = self.aliases.get(head).cloned() {
            let mut caps: Vec<(u8, String)> = tail
                .split_whitespace()
                .enumerate()
                .take(99)
                .map(|(i, w)| ((i + 1) as u8, w.to_string()))
                .collect();
            caps.push((0, tail.to_string()));
            let expanded = pattern::expand(&body, &caps, tail);
            let expanded = if expanded == body && !tail.is_empty() {
                format!("{} {}", body, tail)
            } else {
                expanded
            };
            self.locals.push(BTreeMap::new());
            let _ = self.run_input(&expanded, depth + 1);
            self.locals.pop();
            return Flow::Ok;
        }
        let cmd = self.subst(cmd, depth);
        if self.speedwalk_on
            && let Some(steps) = script::speedwalk(&cmd)
        {
            for step in steps {
                self.send_line(&step);
            }
            return Flow::Ok;
        }
        self.send_line(&cmd);
        Flow::Ok
    }
}

fn next_char(s: &str, i: usize) -> usize {
    let mut j = i + 1;
    while j < s.len() && !s.is_char_boundary(j) {
        j += 1;
    }
    j
}

/// Round a byte offset up to the next character boundary.
///
/// The scan loops advance past a match by a byte or by a replacement's
/// length, either of which can land inside a multi-byte character — and
/// slicing there panics. Server text is full of multi-byte characters (an
/// em-dash is enough), so this is a crash, not a curiosity.
fn ceil_boundary(s: &str, i: usize) -> usize {
    let mut i = i;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Normalize a key event into a macro name like "f5", "ctrl-t", "alt-x".
/// Plain printable keys are never macro-able (they're for typing).
pub fn macro_key_name(key: &crossterm::event::KeyEvent) -> Option<String> {
    use crossterm::event::{KeyCode, KeyModifiers};
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::F(n) => {
            let mut name = String::new();
            if ctrl {
                name.push_str("ctrl-");
            }
            if alt {
                name.push_str("alt-");
            }
            name.push_str(&format!("f{}", n));
            Some(name)
        }
        KeyCode::Char(c) if ctrl || alt => {
            let mut name = String::new();
            if ctrl {
                name.push_str("ctrl-");
            }
            if alt {
                name.push_str("alt-");
            }
            name.push(c.to_ascii_lowercase());
            Some(name)
        }
        KeyCode::Insert => Some("insert".to_string()),
        _ => None,
    }
}

/// Normalize a user-provided macro key spec: "^t" -> "ctrl-t", "F5" -> "f5".
pub fn normalize_key_spec(spec: &str) -> String {
    let s = spec.trim().to_lowercase().replace(' ', "-").replace("ctrl+", "ctrl-").replace("alt+", "alt-");
    if let Some(rest) = s.strip_prefix('^') {
        return format!("ctrl-{}", rest);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(dest: &str, port: Option<u16>) -> (String, u16) {
        match Recipe::parse(dest, port).unwrap() {
            Recipe::Tcp { host, port } => (host, port),
            other => panic!("{dest:?} was not plain tcp: {other:?}"),
        }
    }

    #[test]
    fn a_bare_host_takes_judymuds_telnet_door() {
        assert_eq!(tcp("mudhost", None), ("mudhost".into(), 2323));
        // The classic three-argument form still says the port itself.
        assert_eq!(tcp("mudhost", Some(4000)), ("mudhost".into(), 4000));
    }

    #[test]
    fn a_port_may_ride_along_with_the_host() {
        assert_eq!(tcp("mudhost:4000", None), ("mudhost".into(), 4000));
        // Typed twice, the separate argument is the more deliberate one.
        assert_eq!(tcp("mudhost:4000", Some(23)), ("mudhost".into(), 23));
    }

    #[test]
    fn a_scheme_picks_the_transport_and_its_own_default_door() {
        assert!(matches!(
            Recipe::parse("ssl://mudhost", None),
            Ok(Recipe::Tls { ref host, port: 2324 }) if host == "mudhost"
        ));
        assert!(matches!(
            Recipe::parse("tls://mudhost:9000", None),
            Ok(Recipe::Tls { port: 9000, .. })
        ));
        assert_eq!(tcp("telnet://mudhost", None), ("mudhost".into(), 2323));
        assert_eq!(tcp("tcp://mudhost:99", None), ("mudhost".into(), 99));
    }

    #[test]
    fn ssh_becomes_a_pipe_through_the_system_ssh() {
        let Ok(Recipe::Pipe { label, command, ssh }) = Recipe::parse("ssh://grib@mudhost", None)
        else {
            panic!("ssh:// did not make a pipe")
        };
        assert_eq!(label, "grib@mudhost");
        assert_eq!(ssh.as_deref(), Some("grib@mudhost"));
        // judymud's ssh door, the same default --ssh uses.
        assert!(command.contains("-p 2322"), "{command}");
        assert!(command.contains("grib@mudhost"), "{command}");
    }

    #[test]
    fn an_ssh_port_is_not_written_twice() {
        let Ok(Recipe::Pipe { ssh, .. }) = Recipe::parse("ssh://grib@mudhost:2200", Some(2222))
        else {
            panic!("ssh:// did not make a pipe")
        };
        assert_eq!(ssh.as_deref(), Some("grib@mudhost:2222"));
    }

    #[test]
    fn an_ipv6_address_is_a_host_not_a_host_and_a_port() {
        // The colons are the address. Only brackets can carry a port.
        assert_eq!(tcp("::1", None), ("::1".into(), 2323));
        assert_eq!(tcp("fe80::1", Some(4000)), ("fe80::1".into(), 4000));
        assert_eq!(tcp("[::1]:4000", None), ("::1".into(), 4000));
        assert_eq!(tcp("[::1]", None), ("::1".into(), 2323));
    }

    #[test]
    fn a_destination_that_makes_no_sense_says_so_rather_than_guessing() {
        // Silently defaulting a bad port would connect somewhere unasked for.
        assert!(Recipe::parse("mudhost:99999", None).is_err());
        assert!(Recipe::parse("mudhost:nope", None).is_err());
        assert!(Recipe::parse("gopher://mudhost", None).is_err());
        assert!(Recipe::parse("", None).is_err());
        assert!(Recipe::parse("[::1", None).is_err());
        assert!(Recipe::parse("ssh://", None).is_err());
    }
}
