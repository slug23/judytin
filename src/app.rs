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

#[allow(clippy::large_enum_variant)]
pub enum Ev {
    Key(crossterm::event::KeyEvent),
    Resize(u16, u16),
    Line(String),
    StdinEof,
    Net(u64, Vec<u8>),
    NetClosed(u64, String),
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
    pub(crate) verbatim_on: bool,
    pub(crate) repeat_char: char,
    pub(crate) packet_patch: Duration,
    pub(crate) log_file: Option<std::fs::File>,
    pub(crate) path: Vec<(String, String)>,
    pub(crate) path_pos: usize,
    pub(crate) path_mapping: bool,
    pub(crate) pathdirs: BTreeMap<String, String>,
    conn: Option<Conn>,
    conn_id: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    telnet: Telnet,
    line_buf: String,
    line_written: usize,
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
            verbatim_on: false,
            repeat_char: '!',
            packet_patch: Duration::from_millis(30),
            log_file: None,
            path: Vec::new(),
            path_pos: 0,
            path_mapping: false,
            pathdirs: default_pathdirs(),
            conn: None,
            conn_id: 0,
            host: String::new(),
            port: 0,
            telnet: Telnet::new(),
            line_buf: String::new(),
            line_written: 0,
            flush_deadline: None,
        }
    }

    // ---- output helpers -------------------------------------------------

    /// Raw output (already \r\n-terminated where needed).
    pub fn output(&mut self, raw: &str) {
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
        let state = match &self.conn {
            Some(c) if self.port > 0 => {
                format!("{}:{} ─ {}", self.host, self.port, c.kind())
            }
            Some(c) => format!("{} ─ {}", self.host, c.kind()),
            None => "offline".to_string(),
        };
        let text = format!("judytin ─ {}", state);
        if let Ui::Split(ui) = &mut self.ui {
            let _ = ui.set_status(&text);
        }
    }

    // ---- variables & substitution ---------------------------------------

    pub fn get_var(&self, name: &str) -> Option<String> {
        for scope in self.locals.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Some(v.clone());
            }
        }
        self.vars.get(name).cloned()
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
        let mut caps: Vec<(u8, String)> = args
            .split(';')
            .filter(|a| !a.is_empty())
            .enumerate()
            .take(99)
            .map(|(i, a)| ((i + 1) as u8, a.to_string()))
            .collect();
        caps.push((0, args.clone()));
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

    // ---- networking -----------------------------------------------------

    pub fn connect(&mut self, host: &str, port: u16) {
        if self.conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("trying {}:{} ...", host, port));
        self.conn_id += 1;
        match net::connect_tcp(host, port, self.conn_id, self.tx.clone()) {
            Ok(conn) => self.finish_connect(conn, host, port),
            Err(e) => self.info(&format!("connection to {}:{} failed: {}", host, port, e)),
        }
    }

    pub fn connect_tls(&mut self, host: &str, port: u16) {
        if self.conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("trying {}:{} (tls) ...", host, port));
        self.conn_id += 1;
        match net::connect_tls(host, port, self.conn_id, self.tx.clone()) {
            Ok((conn, pin)) => {
                match pin {
                    Pin::New(fp) => {
                        self.info(&format!("first connection — pinned server cert {}", fp));
                        self.info("(stored in ~/.judytin_known_hosts)");
                    }
                    Pin::Known => self.info("server certificate matches the pinned one"),
                }
                self.finish_connect(conn, host, port);
            }
            Err(e) => self.info(&format!("tls connection to {}:{} failed: {}", host, port, e)),
        }
    }

    pub fn connect_pipe(&mut self, label: &str, command: &str) {
        if self.conn.is_some() {
            self.info("already connected — #zap first");
            return;
        }
        self.info(&format!("running {} ...", command));
        self.conn_id += 1;
        match net::connect_pipe(command, self.conn_id, self.tx.clone()) {
            Ok(conn) => self.finish_connect(conn, label, 0),
            Err(e) => self.info(&format!("cannot run '{}': {}", command, e)),
        }
    }

    fn finish_connect(&mut self, conn: Conn, host: &str, port: u16) {
        let kind = conn.kind();
        self.conn = Some(conn);
        self.host = host.to_string();
        self.port = port;
        self.telnet = Telnet::new();
        self.line_buf.clear();
        self.line_written = 0;
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

    pub fn connected(&self) -> bool {
        self.conn.is_some()
    }

    pub fn disconnect(&mut self, quiet: bool) {
        if let Some(mut conn) = self.conn.take() {
            conn.shutdown();
            if !quiet {
                self.info("connection closed (zap)");
            }
            let (host, port) = (self.host.clone(), self.port.to_string());
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
        if let Some(conn) = &mut self.conn
            && conn.send(bytes).is_err()
        {
            self.info("send failed — connection lost");
            self.disconnect(true);
        }
    }

    pub fn send_line(&mut self, line: &str) {
        if self.conn.is_none() {
            self.info(&format!("not connected — cannot send '{}'. try #session", line));
            return;
        }
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
        let expanded = pattern::expand(&body, &caps, &all);
        self.run_body(&expanded, 1);
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
                if self.conn.is_none() {
                    self.quit = true;
                }
            }
            Ev::Net(id, bytes) => {
                if id == self.conn_id {
                    self.on_net_data(&bytes);
                }
            }
            Ev::NetClosed(id, why) => {
                if id == self.conn_id && self.conn.is_some() {
                    self.conn = None;
                    self.flush_partial();
                    if !self.line_buf.is_empty() {
                        self.output("\r\n");
                        self.line_buf.clear();
                        self.line_written = 0;
                    }
                    self.info(&why);
                    self.update_status();
                    let (host, port) = (self.host.clone(), self.port.to_string());
                    self.fire_event(
                        "SESSION DISCONNECTED",
                        &["judytin".to_string(), host.clone(), host, port],
                    );
                    if matches!(self.ui, Ui::Dumb) {
                        self.quit = true;
                    }
                }
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
        [tick, delay, self.flush_deadline]
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
        let due: Vec<(String, String)> = self
            .tickers
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, t)| (k.clone(), t.body.clone()))
            .collect();
        for (name, body) in due {
            if let Some(t) = self.tickers.get_mut(&name) {
                while t.next <= now {
                    t.next += t.interval;
                }
            }
            self.run_body(&body, 1);
        }
        let due: Vec<String> = self
            .delays
            .iter()
            .filter(|(_, t)| t.next <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for name in due {
            if let Some(t) = self.delays.remove(&name) {
                self.run_body(&t.body, 1);
            }
        }
    }

    // ---- server output pipeline ----------------------------------------

    fn on_net_data(&mut self, bytes: &[u8]) {
        let (data, reply) = self.telnet.feed(bytes);
        if !reply.is_empty() {
            self.send_raw(&reply);
        }
        if let Ui::Split(ui) = &mut self.ui {
            ui.masked = self.telnet.server_echo;
        }
        let text = String::from_utf8_lossy(&data).into_owned();
        for c in text.chars() {
            match c {
                '\n' => self.complete_line(),
                '\r' => {}
                _ => self.line_buf.push(c),
            }
        }
        // Unterminated tail (usually the prompt): hold it briefly so a reply
        // that continues the line still gets full trigger processing, then
        // display it via tick().
        self.flush_deadline = if self.line_buf.len() > self.line_written {
            Some(Instant::now() + self.packet_patch)
        } else {
            None
        };
    }

    /// Display any not-yet-shown part of the current unterminated line
    /// (usually the prompt). Shown raw; triggers run on line completion.
    fn flush_partial(&mut self) {
        self.flush_deadline = None;
        if self.line_buf.len() > self.line_written {
            let frag = self.line_buf[self.line_written..].to_string();
            self.line_written = self.line_buf.len();
            self.output(&frag);
            let full = self.line_buf.clone();
            let (plain, _) = strip_map(&full);
            self.fire_event("RECEIVED PROMPT", &[full, plain]);
        }
    }

    fn complete_line(&mut self) {
        let raw = std::mem::take(&mut self.line_buf);
        let written = std::mem::take(&mut self.line_written);
        let (plain, _) = strip_map(&raw);

        // collect matching action bodies (and count down multishots)
        let mut to_run: Vec<String> = Vec::new();
        let mut spent: Vec<String> = Vec::new();
        for (pat, trig) in &self.actions {
            if let Some(caps) = pattern::matches(pat, &plain) {
                to_run.push(pattern::expand(&trig.body, &caps, &plain));
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
            self.run_body(&body, 1);
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
        if self.echo_on && matches!(self.ui, Ui::Split(_)) && !self.telnet.server_echo {
            // the echo lands right after any dangling prompt, closing its line
            self.output(&format!("\x1b[2m{}\x1b[0m\r\n", line));
            self.line_buf.clear();
            self.line_written = 0;
        }
        if matches!(self.ui, Ui::Dumb) {
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
