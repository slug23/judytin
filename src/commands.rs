//! All # commands: dispatch, flow control, and the tt++ command set.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::ansi::{color_code, strip_map, RESET};
use crate::app::{normalize_key_spec, App, Flow, SwitchCtx, Timed, Trigger, Ui};
use crate::expr::{self, Value};
use crate::fmt;
use crate::pattern;
use crate::script::{get_arg, get_tail};

const COMMANDS: &[&str] = &[
    "action", "alias", "bell", "break", "buffer", "case", "class", "commands", "config",
    "continue", "cr", "default", "delay", "echo", "else", "elseif", "end", "event",
    "foreach", "format", "function", "gag", "grep", "help", "highlight", "history", "if",
    "info", "kill", "line", "local", "log", "loop", "macro", "math", "message", "nop",
    "path", "pathdir", "read", "return", "run", "send", "session", "showme", "split",
    "ssl", "substitute", "switch", "system", "tab", "textin", "ticker", "unaction", "unalias",
    "undelay", "unevent", "unfunction", "ungag", "unhighlight", "unmacro",
    "unsubstitute", "untab", "unticker", "unvariable", "variable", "while", "write",
    "zap",
];

impl App {
    pub(crate) fn tintin_command(
        &mut self,
        cmd: &str,
        depth: u32,
        chain: &mut Option<bool>,
    ) -> Flow {
        let (name, rest) = get_arg(cmd);
        let name = name.to_lowercase();
        if name.is_empty() {
            self.info("what? try #help");
            return Flow::Ok;
        }
        // #5 {commands} — the tt++ repeat syntax
        if name.chars().all(|c| c.is_ascii_digit()) {
            *chain = None;
            return self.cmd_repeat(&name, rest, depth);
        }
        let resolved = if COMMANDS.contains(&name.as_str()) {
            name.clone()
        } else {
            let hits: Vec<&&str> = COMMANDS.iter().filter(|c| c.starts_with(&name)).collect();
            match hits.len() {
                1 => hits[0].to_string(),
                0 => {
                    self.info(&format!("unknown command #{} — try #help", name));
                    return Flow::Ok;
                }
                _ => {
                    let list: Vec<String> = hits.iter().map(|h| format!("#{}", h)).collect();
                    self.info(&format!("#{} is ambiguous: {}", name, list.join(", ")));
                    return Flow::Ok;
                }
            }
        };
        if !matches!(resolved.as_str(), "if" | "elseif" | "else") {
            *chain = None;
        }
        match resolved.as_str() {
            "nop" => {}
            "help" => self.cmd_help(),
            "commands" => {
                let list: Vec<String> = COMMANDS.iter().map(|c| format!("#{}", c)).collect();
                let joined = list.join("  ");
                self.output(&format!("\x1b[2m{}\x1b[0m\r\n", joined));
            }
            "end" => {
                self.disconnect(true);
                self.info("goodbye — judytin signing off");
                self.quit = true;
            }
            "zap" => self.disconnect(false),
            "session" => self.cmd_session(rest, depth),
            "ssl" => self.cmd_ssl(rest, depth),
            "run" => self.cmd_run(rest, depth),
            "cr" => self.send_line(""),
            "bell" => self.output("\x07"),
            "send" => {
                let text = self.subst(&get_tail(rest), depth);
                self.send_line(&text);
            }
            "showme" => {
                let text = self.subst(&get_tail(rest), depth);
                self.output(&format!("{}{}\r\n", text, RESET));
            }
            "echo" => return self.cmd_echo(rest, depth),
            "split" => {
                if let Ui::Split(ui) = &mut self.ui {
                    let _ = ui.redraw();
                } else {
                    self.info("no split screen in dumb mode");
                }
            }
            // ---- flow control -------------------------------------------
            "if" => return self.cmd_if(rest, depth, chain),
            "elseif" => return self.cmd_elseif(rest, depth, chain),
            "else" => return self.cmd_else(rest, depth, chain),
            "switch" => return self.cmd_switch(rest, depth),
            "case" => return self.cmd_case(rest, depth),
            "default" => return self.cmd_default(rest, depth),
            "loop" => return self.cmd_loop(rest, depth),
            "while" => return self.cmd_while(rest, depth),
            "foreach" => return self.cmd_foreach(rest, depth),
            "break" => return Flow::Break,
            "continue" => return Flow::Continue,
            "return" => {
                let v = get_tail(rest);
                let v = self.subst(&v, depth);
                self.return_val = Some(v);
                return Flow::Return;
            }
            "math" => self.cmd_math(rest, depth),
            "local" => self.cmd_local(rest, depth),
            "format" => self.cmd_format(rest, depth),
            // ---- triggers -----------------------------------------------
            "alias" => self.cmd_define("alias", rest),
            "unalias" => self.cmd_undefine("alias", rest),
            "action" => self.cmd_action(rest),
            "unaction" => {
                let key = get_tail(rest);
                if self.actions.remove(&key).is_some() {
                    self.info_kind("action", &format!("ok. action {{{}}} removed", key));
                } else {
                    self.info_kind("action", &format!("no action {{{}}}", key));
                }
            }
            "substitute" => self.cmd_define("substitute", rest),
            "unsubstitute" => self.cmd_undefine("substitute", rest),
            "variable" => self.cmd_variable(rest, depth),
            "unvariable" => self.cmd_undefine("variable", rest),
            "function" => self.cmd_define("function", rest),
            "unfunction" => self.cmd_undefine("function", rest),
            "highlight" => self.cmd_highlight(rest),
            "unhighlight" => {
                let pat = get_tail(rest);
                if self.highlights.remove(&pat).is_some() {
                    self.info_kind("highlight", &format!("ok. highlight {{{}}} removed", pat));
                } else {
                    self.info_kind("highlight", &format!("no highlight {{{}}}", pat));
                }
            }
            "gag" => self.cmd_gag(rest),
            "ungag" => {
                let pat = get_tail(rest);
                if self.gags.remove(&pat) {
                    self.info_kind("gag", &format!("ok. gag {{{}}} removed", pat));
                } else {
                    self.info_kind("gag", &format!("no gag {{{}}}", pat));
                }
            }
            "macro" => self.cmd_macro(rest),
            "unmacro" => {
                let key = normalize_key_spec(&get_tail(rest));
                if self.macros.remove(&key).is_some() {
                    self.info_kind("macro", &format!("ok. macro {{{}}} removed", key));
                } else {
                    self.info_kind("macro", &format!("no macro {{{}}}", key));
                }
            }
            "event" => self.cmd_event(rest),
            "unevent" => {
                let key = get_tail(rest);
                if self.events.remove(&key).is_some() {
                    self.info_kind("event", &format!("ok. event {{{}}} removed", key));
                } else {
                    self.info_kind("event", &format!("no event {{{}}}", key));
                }
            }
            "tab" => {
                let word = get_tail(rest);
                if word.is_empty() {
                    let list: Vec<String> = self.tabs.iter().cloned().collect();
                    let joined = list.join(" ");
                    self.info(&format!("tab list: {}", joined));
                } else {
                    self.tabs.insert(word.clone());
                    self.tag_class("tab", &word);
                    self.info_kind("tab", &format!("ok. added {{{}}} to the tab list", word));
                }
            }
            "untab" => {
                let word = get_tail(rest);
                if self.tabs.remove(&word) {
                    self.info_kind("tab", &format!("ok. tab {{{}}} removed", word));
                } else {
                    self.info_kind("tab", &format!("no tab {{{}}}", word));
                }
            }
            // ---- timers -------------------------------------------------
            "ticker" => self.cmd_ticker(rest, depth),
            "unticker" => {
                let name = get_tail(rest);
                if self.tickers.remove(&name).is_some() {
                    self.info_kind("ticker", &format!("ok. ticker {{{}}} removed", name));
                } else {
                    self.info_kind("ticker", &format!("no ticker {{{}}}", name));
                }
            }
            "delay" => self.cmd_delay(rest, depth),
            "undelay" => {
                let name = get_tail(rest);
                if self.delays.remove(&name).is_some() {
                    self.info_kind("delay", &format!("ok. delay {{{}}} removed", name));
                } else {
                    self.info_kind("delay", &format!("no delay {{{}}}", name));
                }
            }
            // ---- organization -------------------------------------------
            "class" => return self.cmd_class(rest, depth),
            "kill" => self.cmd_kill(rest),
            "info" => self.cmd_info(),
            "message" => self.cmd_message(rest),
            "line" => return self.cmd_line(rest, depth),
            "log" => self.cmd_log(rest),
            // ---- buffer & history ---------------------------------------
            "buffer" => self.cmd_buffer(rest),
            "grep" => self.cmd_grep(rest),
            "history" => self.cmd_history(rest),
            // ---- paths --------------------------------------------------
            "path" => self.cmd_path(rest, depth),
            "pathdir" => self.cmd_pathdir(rest),
            // ---- misc ---------------------------------------------------
            "config" => self.cmd_config(rest),
            "read" => self.cmd_read(rest, depth),
            "write" => self.cmd_write(rest),
            "textin" => self.cmd_textin(rest),
            "system" => self.cmd_system(rest, depth),
            _ => unreachable!(),
        }
        Flow::Ok
    }

    // ---- repeat ---------------------------------------------------------

    fn cmd_repeat(&mut self, count: &str, rest: &str, depth: u32) -> Flow {
        let n: u64 = count.parse().unwrap_or(0);
        if n == 0 || n > 10_000 {
            self.info("repeat count must be 1..10000");
            return Flow::Ok;
        }
        // braced form: each group repeated in turn; unbraced: whole tail
        let mut groups: Vec<String> = Vec::new();
        let mut r = rest.trim_start();
        if r.starts_with('{') {
            while !r.is_empty() {
                let (g, next) = get_arg(r);
                groups.push(g);
                r = next.trim_start();
            }
        } else {
            groups.push(get_tail(rest));
        }
        for group in groups {
            if group.is_empty() {
                continue;
            }
            for _ in 0..n {
                match self.run_input(&group, depth + 1) {
                    Flow::Break => return Flow::Ok,
                    Flow::Continue | Flow::Ok => {}
                    Flow::Return => return Flow::Return,
                }
            }
        }
        Flow::Ok
    }

    // ---- flow control ---------------------------------------------------

    fn eval_cond(&mut self, cond: &str, depth: u32) -> bool {
        let text = self.subst(cond, depth);
        match expr::eval(&text) {
            Ok(v) => v.truthy(),
            Err(e) => {
                self.info(&format!("#if {{{}}}: {}", text, e));
                false
            }
        }
    }

    fn cmd_if(&mut self, rest: &str, depth: u32, chain: &mut Option<bool>) -> Flow {
        let (cond, r2) = get_arg(rest);
        let (then, r3) = get_arg(r2);
        let otherwise = get_tail(r3);
        let hit = self.eval_cond(&cond, depth);
        *chain = Some(hit);
        if hit {
            self.run_input(&then, depth + 1)
        } else if !otherwise.is_empty() {
            *chain = Some(true); // inline else consumed the chain
            self.run_input(&otherwise, depth + 1)
        } else {
            Flow::Ok
        }
    }

    fn cmd_elseif(&mut self, rest: &str, depth: u32, chain: &mut Option<bool>) -> Flow {
        match *chain {
            None => {
                self.info("#elseif without #if");
                Flow::Ok
            }
            Some(true) => Flow::Ok,
            Some(false) => {
                let (cond, r2) = get_arg(rest);
                let then = get_tail(r2);
                if self.eval_cond(&cond, depth) {
                    *chain = Some(true);
                    self.run_input(&then, depth + 1)
                } else {
                    Flow::Ok
                }
            }
        }
    }

    fn cmd_else(&mut self, rest: &str, depth: u32, chain: &mut Option<bool>) -> Flow {
        match *chain {
            None => {
                self.info("#else without #if");
                Flow::Ok
            }
            Some(true) => {
                *chain = None;
                Flow::Ok
            }
            Some(false) => {
                *chain = None;
                self.run_input(&get_tail(rest), depth + 1)
            }
        }
    }

    fn eval_value(&mut self, text: &str, depth: u32) -> Value {
        let text = self.subst(text, depth);
        expr::eval(&text).unwrap_or(Value::Str(text))
    }

    fn cmd_switch(&mut self, rest: &str, depth: u32) -> Flow {
        let (cond, r2) = get_arg(rest);
        let body = get_tail(r2);
        let value = self.eval_value(&cond, depth);
        self.switch_stack.push(SwitchCtx { value, matched: false });
        let flow = self.run_input(&body, depth + 1);
        self.switch_stack.pop();
        flow
    }

    fn cmd_case(&mut self, rest: &str, depth: u32) -> Flow {
        let (val, r2) = get_arg(rest);
        let body = get_tail(r2);
        let Some(top) = self.switch_stack.last() else {
            self.info("#case outside #switch");
            return Flow::Ok;
        };
        if top.matched {
            return Flow::Ok;
        }
        let switch_val = top.value.clone();
        let case_val = self.eval_value(&val, depth);
        let hit = match (&switch_val, &case_val) {
            (Value::Str(s), _) | (_, Value::Str(s)) => {
                let other = if matches!(switch_val, Value::Str(_)) {
                    case_val.display()
                } else {
                    switch_val.display()
                };
                pattern::matches_full(&case_val.display(), &switch_val.display())
                    || (*s == other)
            }
            _ => switch_val.display() == case_val.display(),
        };
        if hit {
            if let Some(top) = self.switch_stack.last_mut() {
                top.matched = true;
            }
            return self.run_input(&body, depth + 1);
        }
        Flow::Ok
    }

    fn cmd_default(&mut self, rest: &str, depth: u32) -> Flow {
        let body = get_tail(rest);
        let Some(top) = self.switch_stack.last_mut() else {
            self.info("#default outside #switch");
            return Flow::Ok;
        };
        if top.matched {
            return Flow::Ok;
        }
        top.matched = true;
        self.run_input(&body, depth + 1)
    }

    fn cmd_loop(&mut self, rest: &str, depth: u32) -> Flow {
        let (a, r2) = get_arg(rest);
        let (b, r3) = get_arg(r2);
        let (var, r4) = get_arg(r3);
        let body = get_tail(r4);
        let start = self.eval_value(&a, depth).display().parse::<i64>().unwrap_or(0);
        let end = self.eval_value(&b, depth).display().parse::<i64>().unwrap_or(0);
        if var.is_empty() || body.is_empty() {
            self.info("usage: #loop {start} {end} {variable} {commands}");
            return Flow::Ok;
        }
        if (start - end).abs() > 100_000 {
            self.info("loop range too large");
            return Flow::Ok;
        }
        let step = if start <= end { 1 } else { -1 };
        let mut i = start;
        loop {
            self.set_var(&var, &i.to_string());
            match self.run_input(&body, depth + 1) {
                Flow::Break => break,
                Flow::Return => return Flow::Return,
                Flow::Continue | Flow::Ok => {}
            }
            if i == end {
                break;
            }
            i += step;
        }
        Flow::Ok
    }

    fn cmd_while(&mut self, rest: &str, depth: u32) -> Flow {
        let (cond, r2) = get_arg(rest);
        let body = get_tail(r2);
        if body.is_empty() {
            self.info("usage: #while {conditional} {commands}");
            return Flow::Ok;
        }
        let mut guard = 0u32;
        while self.eval_cond(&cond, depth) {
            guard += 1;
            if guard > 100_000 {
                self.info("#while ran 100000 iterations — breaking out");
                break;
            }
            match self.run_input(&body, depth + 1) {
                Flow::Break => break,
                Flow::Return => return Flow::Return,
                Flow::Continue | Flow::Ok => {}
            }
        }
        Flow::Ok
    }

    fn cmd_foreach(&mut self, rest: &str, depth: u32) -> Flow {
        let (list_raw, r2) = get_arg(rest);
        let (var, r3) = get_arg(r2);
        let body = get_tail(r3);
        if var.is_empty() || body.is_empty() {
            self.info("usage: #foreach {list} {variable} {commands}");
            return Flow::Ok;
        }
        let list = self.subst(&list_raw, depth);
        // items are {a}{b}{c} or a;b;c
        let mut items: Vec<String> = Vec::new();
        let trimmed = list.trim();
        if trimmed.starts_with('{') {
            let mut r = trimmed;
            while !r.is_empty() {
                let (item, next) = get_arg(r);
                items.push(item);
                r = next.trim_start();
            }
        } else {
            items = trimmed.split(';').map(|s| s.to_string()).collect();
        }
        for item in items {
            if item.is_empty() {
                continue;
            }
            self.set_var(&var, &item);
            match self.run_input(&body, depth + 1) {
                Flow::Break => break,
                Flow::Return => return Flow::Return,
                Flow::Continue | Flow::Ok => {}
            }
        }
        Flow::Ok
    }

    fn cmd_math(&mut self, rest: &str, depth: u32) {
        let (var, r2) = get_arg(rest);
        let e = get_tail(r2);
        if var.is_empty() || e.is_empty() {
            self.info("usage: #math {variable} {expression}");
            return;
        }
        let text = self.subst(&e, depth);
        match expr::eval(&text) {
            Ok(v) => {
                let shown = v.display();
                self.set_var(&var, &shown);
                self.info_kind("variable", &format!("ok. math {{{}}} = {{{}}}", var, shown));
            }
            Err(err) => self.info(&format!("#math {{{}}}: {}", text, err)),
        }
    }

    fn cmd_local(&mut self, rest: &str, depth: u32) {
        let (var, r2) = get_arg(rest);
        let val = get_tail(r2);
        if var.is_empty() {
            self.info("usage: #local {variable} {value}");
            return;
        }
        let val = self.subst(&val, depth);
        self.set_local(&var, &val);
        self.info_kind("variable", &format!("ok. local {{{}}} = {{{}}}", var, val));
    }

    fn cmd_format(&mut self, rest: &str, depth: u32) {
        let (var, r2) = get_arg(rest);
        let (fmt_s, mut r) = get_arg(r2);
        if var.is_empty() || fmt_s.is_empty() {
            self.info("usage: #format {variable} {format} {args...}");
            return;
        }
        let mut args: Vec<String> = Vec::new();
        loop {
            let trimmed = r.trim_start();
            if trimmed.is_empty() {
                break;
            }
            let (a, next) = get_arg(trimmed);
            args.push(self.subst(&a, depth));
            r = next;
        }
        let fmt_s = self.subst(&fmt_s, depth);
        match fmt::format(&fmt_s, &args) {
            Ok(v) => {
                self.set_var(&var, &v);
                self.info_kind("variable", &format!("ok. format {{{}}} = {{{}}}", var, v));
            }
            Err(e) => self.info(&format!("#format: {}", e)),
        }
    }

    fn cmd_echo(&mut self, rest: &str, depth: u32) -> Flow {
        let (fmt_s, mut r) = get_arg(rest);
        let mut args: Vec<String> = Vec::new();
        loop {
            let trimmed = r.trim_start();
            if trimmed.is_empty() {
                break;
            }
            let (a, next) = get_arg(trimmed);
            args.push(self.subst(&a, depth));
            r = next;
        }
        let fmt_s = self.subst(&fmt_s, depth);
        match fmt::format(&fmt_s, &args) {
            Ok(v) => self.output(&format!("{}{}\r\n", v, RESET)),
            Err(e) => self.info(&format!("#echo: {}", e)),
        }
        Flow::Ok
    }

    // ---- trigger definition ---------------------------------------------

    fn table_mut(&mut self, kind: &str) -> &mut BTreeMap<String, String> {
        match kind {
            "alias" => &mut self.aliases,
            "substitute" => &mut self.subs,
            "variable" => &mut self.vars,
            "function" => &mut self.functions,
            _ => unreachable!("no plain table for {}", kind),
        }
    }

    pub(crate) fn tag_class(&mut self, kind: &str, key: &str) {
        if let Some(class) = self.current_class.clone() {
            let entry = (kind.to_string(), key.to_string());
            let list = self.class_index.entry(class).or_default();
            if !list.contains(&entry) {
                list.push(entry);
            }
        }
    }

    fn cmd_define(&mut self, kind: &str, rest: &str) {
        let (key, r2) = get_arg(rest);
        let val = get_tail(r2);
        if key.is_empty() {
            let snapshot = self.table_mut(kind).clone();
            self.cmd_list(kind, &snapshot);
        } else if val.is_empty() {
            match self.table_mut(kind).get(&key).cloned() {
                Some(v) => self.info(&format!("#{} {{{}}} {{{}}}", kind, key, v)),
                None => self.info(&format!("no {} {{{}}}", kind, key)),
            }
        } else {
            self.table_mut(kind).insert(key.clone(), val.clone());
            self.tag_class(kind, &key);
            self.info_kind(kind, &format!("ok. {} {{{}}} = {{{}}}", kind, key, val));
        }
    }

    fn cmd_undefine(&mut self, kind: &str, rest: &str) {
        let key = get_tail(rest);
        if self.table_mut(kind).remove(&key).is_some() {
            self.info_kind(kind, &format!("ok. {} {{{}}} removed", kind, key));
        } else {
            self.info_kind(kind, &format!("no {} {{{}}}", kind, key));
        }
    }

    fn cmd_variable(&mut self, rest: &str, depth: u32) {
        let (key, r2) = get_arg(rest);
        let val = get_tail(r2);
        if key.is_empty() || val.is_empty() {
            self.cmd_define("variable", rest);
            return;
        }
        // variables store their substituted value (tt++ copies content)
        let val = self.subst(&val, depth);
        self.vars.insert(key.clone(), val.clone());
        self.tag_class("variable", &key);
        self.info_kind("variable", &format!("ok. variable {{{}}} = {{{}}}", key, val));
    }

    fn cmd_action(&mut self, rest: &str) {
        let (pat, r2) = get_arg(rest);
        let body = get_tail(r2);
        if pat.is_empty() {
            let snapshot: BTreeMap<String, String> = self
                .actions
                .iter()
                .map(|(k, t)| (k.clone(), t.body.clone()))
                .collect();
            self.cmd_list("action", &snapshot);
        } else if body.is_empty() {
            match self.actions.get(&pat) {
                Some(t) => {
                    let b = t.body.clone();
                    self.info(&format!("#action {{{}}} {{{}}}", pat, b));
                }
                None => self.info(&format!("no action {{{}}}", pat)),
            }
        } else {
            self.actions.insert(
                pat.clone(),
                Trigger { body: body.clone(), shots: self.shots_mode },
            );
            self.tag_class("action", &pat);
            self.info_kind("action", &format!("ok. action {{{}}} = {{{}}}", pat, body));
        }
    }

    fn cmd_highlight(&mut self, rest: &str) {
        let (pat, r2) = get_arg(rest);
        let color = get_tail(r2);
        if pat.is_empty() {
            self.cmd_list("highlight", &self.highlights.clone());
        } else if color.is_empty() {
            self.info("usage: #highlight {pattern} {color}");
        } else if color_code(&color).is_none() {
            self.info(&format!(
                "unknown color '{}' (try: red, light yellow, Orange, <faa>, reverse, ...)",
                color
            ));
        } else {
            self.highlights.insert(pat.clone(), color.clone());
            self.tag_class("highlight", &pat);
            self.info_kind(
                "highlight",
                &format!("ok. {{{}}} now highlights in {{{}}}", pat, color),
            );
        }
    }

    fn cmd_gag(&mut self, rest: &str) {
        let pat = get_tail(rest);
        if pat.is_empty() {
            let list: Vec<String> = self.gags.iter().map(|g| format!("  #gag {{{}}}", g)).collect();
            if list.is_empty() {
                self.info("no gags defined");
            } else {
                let joined = list.join("\r\n");
                self.output(&format!("{}\r\n", joined));
            }
        } else {
            self.gags.insert(pat.clone());
            self.tag_class("gag", &pat);
            self.info_kind("gag", &format!("ok. lines matching {{{}}} are gagged", pat));
        }
    }

    fn cmd_macro(&mut self, rest: &str) {
        let (key, r2) = get_arg(rest);
        let body = get_tail(r2);
        if key.is_empty() {
            let snapshot = self.macros.clone();
            self.cmd_list("macro", &snapshot);
            return;
        }
        let key = normalize_key_spec(&key);
        if body.is_empty() {
            match self.macros.get(&key).cloned() {
                Some(b) => self.info(&format!("#macro {{{}}} {{{}}}", key, b)),
                None => self.info(&format!("no macro {{{}}}", key)),
            }
            return;
        }
        // sanity check the key spec
        let known = key.starts_with("ctrl-")
            || key.starts_with("alt-")
            || key == "insert"
            || (key.starts_with('f')
                && key[1..].parse::<u8>().map(|n| (1..=12).contains(&n)).unwrap_or(false));
        if !known {
            self.info("macro keys: f1-f12, ctrl-<key> (or ^<key>), alt-<key>, insert");
            return;
        }
        self.macros.insert(key.clone(), body.clone());
        self.tag_class("macro", &key);
        self.info_kind("macro", &format!("ok. macro {{{}}} = {{{}}}", key, body));
    }

    fn cmd_event(&mut self, rest: &str) {
        let (name, r2) = get_arg(rest);
        let body = get_tail(r2);
        if name.is_empty() {
            let snapshot = self.events.clone();
            self.cmd_list("event", &snapshot);
            return;
        }
        let known = [
            "SESSION CONNECTED",
            "SESSION DISCONNECTED",
            "RECEIVED LINE",
            "RECEIVED PROMPT",
        ];
        if !known.contains(&name.as_str()) {
            self.info(&format!(
                "unknown event {{{}}} — supported: {}",
                name,
                known.join(", ")
            ));
            return;
        }
        if body.is_empty() {
            match self.events.get(&name).cloned() {
                Some(b) => self.info(&format!("#event {{{}}} {{{}}}", name, b)),
                None => self.info(&format!("no event {{{}}}", name)),
            }
            return;
        }
        self.events.insert(name.clone(), body.clone());
        self.tag_class("event", &name);
        self.info_kind("event", &format!("ok. event {{{}}} = {{{}}}", name, body));
    }

    fn cmd_list(&mut self, kind: &str, table: &BTreeMap<String, String>) {
        if table.is_empty() {
            self.info(&format!("no {}s defined", kind));
            return;
        }
        let lines: Vec<String> = table
            .iter()
            .map(|(k, v)| format!("  #{} {{{}}} {{{}}}", kind, k, v))
            .collect();
        let joined = lines.join("\r\n");
        self.output(&format!("{}\r\n", joined));
    }

    // ---- timers ---------------------------------------------------------

    fn cmd_ticker(&mut self, rest: &str, depth: u32) {
        let (name, r2) = get_arg(rest);
        let (body, r3) = get_arg(r2);
        let (secs_s, _) = get_arg(r3);
        if name.is_empty() {
            let lines: Vec<String> = self
                .tickers
                .iter()
                .map(|(k, t)| {
                    format!("  #ticker {{{}}} {{{}}} {{{}}}", k, t.body, t.interval.as_secs_f64())
                })
                .collect();
            if lines.is_empty() {
                self.info("no tickers defined");
            } else {
                let joined = lines.join("\r\n");
                self.output(&format!("{}\r\n", joined));
            }
            return;
        }
        let secs_s = self.subst(&secs_s, depth);
        let secs: f64 = match secs_s.parse() {
            Ok(s) if s > 0.0 => s,
            _ => {
                self.info("usage: #ticker {name} {commands} {seconds}");
                return;
            }
        };
        let interval = Duration::from_secs_f64(secs);
        self.tickers.insert(
            name.clone(),
            Timed { body, interval, next: Instant::now() + interval },
        );
        self.tag_class("ticker", &name);
        self.info_kind("ticker", &format!("ok. ticker {{{}}} fires every {}s", name, secs));
    }

    fn cmd_delay(&mut self, rest: &str, depth: u32) {
        let (a, r2) = get_arg(rest);
        let (b, r3) = get_arg(r2);
        let c = get_tail(r3);
        if a.is_empty() {
            let lines: Vec<String> = self
                .delays
                .iter()
                .map(|(k, t)| format!("  #delay {{{}}} {{{}}}", k, t.body))
                .collect();
            if lines.is_empty() {
                self.info("no delays pending");
            } else {
                let joined = lines.join("\r\n");
                self.output(&format!("{}\r\n", joined));
            }
            return;
        }
        let (name, body, secs_s) = if c.is_empty() {
            self.delay_counter += 1;
            (format!("{}", self.delay_counter), b, a)
        } else {
            (a, b, c)
        };
        let secs_s = self.subst(&secs_s, depth);
        let secs: f64 = match secs_s.trim().parse() {
            Ok(s) if s >= 0.0 => s,
            _ => {
                self.info("usage: #delay {seconds} {commands} or #delay {name} {commands} {seconds}");
                return;
            }
        };
        self.delays.insert(
            name.clone(),
            Timed {
                body,
                interval: Duration::from_secs_f64(secs),
                next: Instant::now() + Duration::from_secs_f64(secs),
            },
        );
        self.info_kind("delay", &format!("ok. delay {{{}}} fires in {}s", name, secs));
    }

    // ---- class / kill / info / message / line / log ---------------------

    fn cmd_class(&mut self, rest: &str, depth: u32) -> Flow {
        let (name, r2) = get_arg(rest);
        let (op, r3) = get_arg(r2);
        let arg = get_tail(r3);
        if name.is_empty() {
            let mut lines: Vec<String> = Vec::new();
            for (class, items) in &self.class_index {
                let open = if Some(class) == self.current_class.as_ref() { " (open)" } else { "" };
                lines.push(format!("  class {{{}}}: {} items{}", class, items.len(), open));
            }
            if lines.is_empty() {
                self.info("no classes defined");
            } else {
                let joined = lines.join("\r\n");
                self.output(&format!("{}\r\n", joined));
            }
            return Flow::Ok;
        }
        match op.to_lowercase().as_str() {
            "open" => {
                self.current_class = Some(name.clone());
                self.class_index.entry(name.clone()).or_default();
                self.info_kind("class", &format!("ok. class {{{}}} is open", name));
            }
            "close" => {
                if self.current_class.as_deref() == Some(name.as_str()) {
                    self.current_class = None;
                }
                self.info_kind("class", &format!("ok. class {{{}}} is closed", name));
            }
            "assign" => {
                let saved = self.current_class.replace(name.clone());
                self.class_index.entry(name.clone()).or_default();
                let _ = self.run_input(&arg, depth + 1);
                self.current_class = saved;
            }
            "read" => {
                let saved = self.current_class.replace(name.clone());
                self.class_index.entry(name.clone()).or_default();
                self.cmd_read(&arg, depth);
                self.current_class = saved;
            }
            "write" => {
                let items = self.class_index.get(&name).cloned().unwrap_or_default();
                let mut out = String::new();
                for (kind, key) in &items {
                    if let Some(line) = self.serialize_item(kind, key) {
                        out.push_str(&line);
                        out.push('\n');
                    }
                }
                if arg.is_empty() {
                    self.info("usage: #class {name} {write} {file}");
                } else {
                    match std::fs::write(&arg, out) {
                        Ok(_) => self.info(&format!("class {{{}}} written to {}", name, arg)),
                        Err(e) => self.info(&format!("cannot write {}: {}", arg, e)),
                    }
                }
            }
            "clear" => {
                let items = self.class_index.get(&name).cloned().unwrap_or_default();
                let n = items.len();
                for (kind, key) in items {
                    self.kill_item(&kind, &key);
                }
                self.class_index.insert(name.clone(), Vec::new());
                self.info_kind("class", &format!("ok. cleared {} items from class {{{}}}", n, name));
            }
            "kill" => {
                let items = self.class_index.remove(&name).unwrap_or_default();
                for (kind, key) in items {
                    self.kill_item(&kind, &key);
                }
                if self.current_class.as_deref() == Some(name.as_str()) {
                    self.current_class = None;
                }
                self.info_kind("class", &format!("ok. class {{{}}} killed", name));
            }
            "list" => {
                let items = self.class_index.get(&name).cloned().unwrap_or_default();
                if items.is_empty() {
                    self.info(&format!("class {{{}}} is empty", name));
                } else {
                    let lines: Vec<String> = items
                        .iter()
                        .filter_map(|(kind, key)| self.serialize_item(kind, key))
                        .map(|l| format!("  {}", l))
                        .collect();
                    let joined = lines.join("\r\n");
                    self.output(&format!("{}\r\n", joined));
                }
            }
            "size" => {
                let n = self.class_index.get(&name).map(|v| v.len()).unwrap_or(0);
                if arg.is_empty() {
                    self.info(&format!("class {{{}}} has {} items", name, n));
                } else {
                    self.set_var(&arg, &n.to_string());
                }
            }
            other => {
                self.info(&format!(
                    "unknown class option '{}' (open close assign read write clear kill list size)",
                    other
                ));
            }
        }
        Flow::Ok
    }

    fn serialize_item(&self, kind: &str, key: &str) -> Option<String> {
        match kind {
            "alias" => self.aliases.get(key).map(|v| format!("#alias {{{}}} {{{}}}", key, v)),
            "action" => self.actions.get(key).map(|t| format!("#action {{{}}} {{{}}}", key, t.body)),
            "substitute" => self.subs.get(key).map(|v| format!("#substitute {{{}}} {{{}}}", key, v)),
            "variable" => self.vars.get(key).map(|v| format!("#variable {{{}}} {{{}}}", key, v)),
            "function" => self.functions.get(key).map(|v| format!("#function {{{}}} {{{}}}", key, v)),
            "highlight" => self.highlights.get(key).map(|v| format!("#highlight {{{}}} {{{}}}", key, v)),
            "gag" => self.gags.contains(key).then(|| format!("#gag {{{}}}", key)),
            "macro" => self.macros.get(key).map(|v| format!("#macro {{{}}} {{{}}}", key, v)),
            "event" => self.events.get(key).map(|v| format!("#event {{{}}} {{{}}}", key, v)),
            "tab" => self.tabs.contains(key).then(|| format!("#tab {{{}}}", key)),
            "ticker" => self.tickers.get(key).map(|t| {
                format!("#ticker {{{}}} {{{}}} {{{}}}", key, t.body, t.interval.as_secs_f64())
            }),
            _ => None,
        }
    }

    fn kill_item(&mut self, kind: &str, key: &str) -> bool {
        match kind {
            "alias" => self.aliases.remove(key).is_some(),
            "action" => self.actions.remove(key).is_some(),
            "substitute" => self.subs.remove(key).is_some(),
            "variable" => self.vars.remove(key).is_some(),
            "function" => self.functions.remove(key).is_some(),
            "highlight" => self.highlights.remove(key).is_some(),
            "gag" => self.gags.remove(key),
            "macro" => self.macros.remove(key).is_some(),
            "event" => self.events.remove(key).is_some(),
            "tab" => self.tabs.remove(key),
            "ticker" => self.tickers.remove(key).is_some(),
            _ => false,
        }
    }

    fn cmd_kill(&mut self, rest: &str) {
        let kind = get_tail(rest).to_lowercase();
        let mut killed: Vec<&str> = Vec::new();
        let all = kind.is_empty() || kind == "all";
        macro_rules! wipe {
            ($name:literal, $field:expr) => {
                if all || kind == $name {
                    $field;
                    killed.push($name);
                }
            };
        }
        wipe!("alias", self.aliases.clear());
        wipe!("action", self.actions.clear());
        wipe!("substitute", self.subs.clear());
        wipe!("variable", self.vars.clear());
        wipe!("function", self.functions.clear());
        wipe!("highlight", self.highlights.clear());
        wipe!("gag", self.gags.clear());
        wipe!("macro", self.macros.clear());
        wipe!("event", self.events.clear());
        wipe!("tab", self.tabs.clear());
        wipe!("ticker", self.tickers.clear());
        wipe!("delay", self.delays.clear());
        wipe!("path", {
            self.path.clear();
            self.path_pos = 0;
        });
        if all {
            self.class_index.clear();
            self.current_class = None;
            self.info("ok. killed everything");
        } else if killed.is_empty() {
            self.info(&format!("unknown kill target '{}'", kind));
        } else {
            self.info(&format!("ok. killed all {}s", killed.join(", ")));
        }
    }

    fn cmd_info(&mut self) {
        let msg = format!(
            "aliases {}, actions {}, subs {}, highlights {}, gags {}, vars {}, functions {}, \
             macros {}, events {}, tabs {}, tickers {}, delays {}, classes {}, path steps {}",
            self.aliases.len(),
            self.actions.len(),
            self.subs.len(),
            self.highlights.len(),
            self.gags.len(),
            self.vars.len(),
            self.functions.len(),
            self.macros.len(),
            self.events.len(),
            self.tabs.len(),
            self.tickers.len(),
            self.delays.len(),
            self.class_index.len(),
            self.path.len(),
        );
        self.info(&msg);
    }

    fn cmd_message(&mut self, rest: &str) {
        let (kind, r2) = get_arg(rest);
        let (state, _) = get_arg(r2);
        if kind.is_empty() {
            let off: Vec<String> = self.msg_off.iter().cloned().collect();
            if off.is_empty() {
                self.info("all messages are on");
            } else {
                self.info(&format!("messages off for: {}", off.join(", ")));
            }
            return;
        }
        let kind = kind.to_lowercase();
        if state.eq_ignore_ascii_case("off") {
            self.msg_off.insert(kind.clone());
            self.info(&format!("ok. messages for {} are off", kind));
        } else {
            self.msg_off.remove(&kind);
            self.info(&format!("ok. messages for {} are on", kind));
        }
    }

    fn cmd_line(&mut self, rest: &str, depth: u32) -> Flow {
        let (op, r2) = get_arg(rest);
        let arg = get_tail(r2);
        match op.to_lowercase().as_str() {
            "gag" => {
                let n: u32 = if arg.is_empty() { 1 } else { arg.trim().parse().unwrap_or(1) };
                self.gag_next = self.gag_next.saturating_add(n);
            }
            "oneshot" => {
                let saved = self.shots_mode;
                self.shots_mode = Some(1);
                let flow = self.run_input(&arg, depth + 1);
                self.shots_mode = saved;
                return flow;
            }
            "multishot" => {
                let (n_s, r) = get_arg(&arg);
                let n: u32 = n_s.trim().parse().unwrap_or(1);
                let saved = self.shots_mode;
                self.shots_mode = Some(n.max(1));
                let flow = self.run_input(&get_tail(r), depth + 1);
                self.shots_mode = saved;
                return flow;
            }
            "quiet" => {
                self.quiet += 1;
                let flow = self.run_input(&arg, depth + 1);
                self.quiet -= 1;
                return flow;
            }
            "ignore" => return self.run_input(&arg, depth + 1),
            "verbatim" => self.send_line(&arg),
            other => {
                self.info(&format!(
                    "unknown line option '{}' (gag oneshot multishot quiet ignore verbatim)",
                    other
                ));
            }
        }
        Flow::Ok
    }

    fn cmd_log(&mut self, rest: &str) {
        let (op, r2) = get_arg(rest);
        let file = get_tail(r2);
        match op.to_lowercase().as_str() {
            "append" | "overwrite" => {
                if file.is_empty() {
                    self.info("usage: #log {append|overwrite|off} {file}");
                    return;
                }
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(op.eq_ignore_ascii_case("append"))
                    .write(true)
                    .truncate(op.eq_ignore_ascii_case("overwrite"))
                    .open(&file);
                match f {
                    Ok(f) => {
                        self.log_file = Some(f);
                        self.info(&format!("logging to {} ({})", file, op));
                    }
                    Err(e) => self.info(&format!("cannot open {}: {}", file, e)),
                }
            }
            "off" | "" => {
                self.log_file = None;
                self.info("logging off");
            }
            other => self.info(&format!("unknown log option '{}' (append overwrite off)", other)),
        }
    }

    // ---- buffer / grep / history ----------------------------------------

    fn cmd_buffer(&mut self, rest: &str) {
        let (op, r2) = get_arg(rest);
        let arg = get_tail(r2);
        let Ui::Split(ui) = &mut self.ui else {
            self.info("no scrollback in dumb mode");
            return;
        };
        match op.to_lowercase().as_str() {
            "up" => {
                let _ = if arg.is_empty() {
                    ui.buffer_page(-1)
                } else {
                    ui.buffer_scroll(-arg.trim().parse::<i64>().unwrap_or(0))
                };
            }
            "down" => {
                let _ = if arg.is_empty() {
                    ui.buffer_page(1)
                } else {
                    ui.buffer_scroll(arg.trim().parse::<i64>().unwrap_or(0))
                };
            }
            "home" => {
                let _ = ui.buffer_home();
            }
            "end" => {
                let _ = ui.buffer_end();
            }
            "clear" => {
                let _ = ui.buffer_clear();
            }
            "find" => {
                if arg.is_empty() {
                    self.info("usage: #buffer {find} {pattern}");
                    return;
                }
                let compiled = pattern::compile(&arg);
                let mut hit = None;
                for (i, line) in ui.buffer_lines().enumerate() {
                    let (plain, _) = strip_map(line);
                    if pattern::find(&compiled, &plain).is_some() {
                        hit = Some(i);
                    }
                }
                match hit {
                    Some(i) => {
                        let _ = ui.buffer_jump(i);
                    }
                    None => self.info(&format!("no line matching {{{}}}", arg)),
                }
            }
            "info" | "" => {
                let len = ui.buffer_len();
                let off = ui.scroll_offset();
                self.info(&format!("scrollback: {} lines, offset {}", len, off));
            }
            other => self.info(&format!(
                "unknown buffer option '{}' (up down home end clear find info)",
                other
            )),
        }
    }

    fn cmd_grep(&mut self, rest: &str) {
        let pat = get_tail(rest);
        if pat.is_empty() {
            self.info("usage: #grep {pattern}");
            return;
        }
        let Ui::Split(ui) = &self.ui else {
            self.info("no scrollback in dumb mode");
            return;
        };
        let compiled = pattern::compile(&pat);
        let mut hits: Vec<String> = Vec::new();
        for line in ui.buffer_lines() {
            let (plain, _) = strip_map(line);
            if pattern::find(&compiled, &plain).is_some() {
                hits.push(line.clone());
            }
        }
        let total = hits.len();
        let shown: Vec<String> = hits.into_iter().rev().take(20).rev().collect();
        if shown.is_empty() {
            self.info(&format!("no lines match {{{}}}", pat));
        } else {
            let joined = shown.join("\x1b[0m\r\n");
            self.output(&format!("{}\x1b[0m\r\n", joined));
            self.info(&format!("{} of {} matching lines", shown.len(), total));
        }
    }

    fn cmd_history(&mut self, rest: &str) {
        let op = get_tail(rest).to_lowercase();
        let Ui::Split(ui) = &mut self.ui else {
            self.info("no history in dumb mode");
            return;
        };
        if op == "clear" {
            ui.history_clear();
            self.info("history cleared");
            return;
        }
        let hist: Vec<String> = ui.history().to_vec();
        if hist.is_empty() {
            self.info("history is empty");
            return;
        }
        let start = hist.len().saturating_sub(20);
        let lines: Vec<String> = hist
            .iter()
            .enumerate()
            .skip(start)
            .map(|(i, h)| format!("  \x1b[2m{:4}\x1b[0m {}", i + 1, h))
            .collect();
        let joined = lines.join("\r\n");
        self.output(&format!("{}\r\n", joined));
        self.info(&format!("{}<n> repeats an entry, {}{} repeats the last", self.repeat_char, self.repeat_char, self.repeat_char));
    }

    // ---- path -----------------------------------------------------------

    fn cmd_path(&mut self, rest: &str, depth: u32) {
        let (op, r2) = get_arg(rest);
        let arg_raw = r2;
        match op.to_lowercase().as_str() {
            "create" | "new" => {
                self.path.clear();
                self.path_pos = 0;
                self.path_mapping = true;
                self.info("path cleared, mapping started");
            }
            "start" => {
                self.path_mapping = true;
                self.info("path mapping started");
            }
            "stop" => {
                self.path_mapping = false;
                self.info("path mapping stopped");
            }
            "destroy" => {
                self.path.clear();
                self.path_pos = 0;
                self.path_mapping = false;
                self.info("path destroyed");
            }
            "delete" => {
                if self.path.pop().is_some() {
                    self.path_pos = self.path_pos.min(self.path.len());
                    self.info("last step deleted");
                } else {
                    self.info("path is empty");
                }
            }
            "describe" => {
                let fwd: Vec<String> = self.path.iter().map(|(f, _)| f.clone()).collect();
                let state = if self.path_mapping { "mapping" } else { "idle" };
                let msg = format!(
                    "path ({}, position {}/{}): {}",
                    state,
                    self.path_pos,
                    self.path.len(),
                    if fwd.is_empty() { "(empty)".to_string() } else { fwd.join(";") }
                );
                self.info(&msg);
            }
            "insert" | "ins" => {
                let (fwd, r3) = get_arg(arg_raw);
                let bwd = get_tail(r3);
                if fwd.is_empty() {
                    self.info("usage: #path insert {forward} {backward}");
                } else {
                    let bwd = if bwd.is_empty() {
                        self.pathdirs.get(&fwd).cloned().unwrap_or_default()
                    } else {
                        bwd
                    };
                    self.path.push((fwd, bwd));
                    self.path_pos = self.path.len();
                    self.info("step inserted");
                }
            }
            "walk" => {
                let back = get_tail(arg_raw).to_lowercase().starts_with('b');
                if back {
                    if self.path_pos == 0 {
                        self.info("at the start of the path");
                    } else {
                        self.path_pos -= 1;
                        let step = self.path[self.path_pos].1.clone();
                        self.send_line(&step);
                    }
                } else if self.path_pos >= self.path.len() {
                    self.info("at the end of the path");
                } else {
                    let step = self.path[self.path_pos].0.clone();
                    self.path_pos += 1;
                    self.send_line(&step);
                }
            }
            "goto" => {
                let a = get_tail(arg_raw).to_lowercase();
                if a == "start" {
                    self.path_pos = 0;
                } else if a == "end" {
                    self.path_pos = self.path.len();
                } else if let Ok(n) = a.parse::<usize>() {
                    self.path_pos = n.min(self.path.len());
                }
                self.info(&format!("position {}/{}", self.path_pos, self.path.len()));
            }
            "run" => {
                let was_mapping = std::mem::take(&mut self.path_mapping);
                let delay: f64 = get_tail(arg_raw).trim().parse().unwrap_or(0.0);
                let steps: Vec<String> =
                    self.path[self.path_pos.min(self.path.len())..]
                        .iter()
                        .map(|(f, _)| f.clone())
                        .collect();
                if delay > 0.0 {
                    for (i, step) in steps.iter().enumerate() {
                        self.delay_counter += 1;
                        let name = format!("path{}", self.delay_counter);
                        let after = Duration::from_secs_f64(delay * (i + 1) as f64);
                        self.delays.insert(
                            name,
                            Timed {
                                body: format!("#send {{{}}}", step),
                                interval: after,
                                next: Instant::now() + after,
                            },
                        );
                    }
                } else {
                    for step in steps {
                        self.send_line(&step);
                    }
                }
                self.path_pos = self.path.len();
                self.path_mapping = was_mapping;
            }
            "swap" => {
                self.path = self.path.iter().rev().map(|(f, b)| (b.clone(), f.clone())).collect();
                self.path_pos = 0;
                self.info("path reversed");
            }
            "zip" => {
                let walk = zip_speedwalk(&self.path);
                let var = get_tail(arg_raw);
                if var.is_empty() {
                    self.info(&format!("speedwalk: {}", walk));
                } else {
                    self.set_var(&var, &walk);
                }
            }
            "unzip" => {
                let walk = self.subst(&get_tail(arg_raw), depth);
                match crate::script::speedwalk(&walk) {
                    Some(steps) => {
                        self.path = steps
                            .into_iter()
                            .map(|s| {
                                let rev = self.pathdirs.get(&s).cloned().unwrap_or_default();
                                (s, rev)
                            })
                            .collect();
                        self.path_pos = 0;
                        self.info(&format!("path loaded, {} steps", self.path.len()));
                    }
                    None => self.info(&format!("'{}' is not a speedwalk", walk)),
                }
            }
            "save" => {
                let (dir, r3) = get_arg(arg_raw);
                let var = get_tail(r3);
                if var.is_empty() {
                    self.info("usage: #path save {forward|backward} {variable}");
                    return;
                }
                let steps: Vec<String> = if dir.to_lowercase().starts_with('b') {
                    self.path.iter().rev().map(|(_, b)| b.clone()).collect()
                } else {
                    self.path.iter().map(|(f, _)| f.clone()).collect()
                };
                self.set_var(&var, &steps.join(";"));
                self.info_kind("variable", &format!("ok. path saved to {{{}}}", var));
            }
            other => self.info(&format!(
                "unknown path option '{}' (create start stop destroy delete describe insert walk goto run swap zip unzip save)",
                other
            )),
        }
    }

    fn cmd_pathdir(&mut self, rest: &str) {
        let (dir, r2) = get_arg(rest);
        let rev = get_tail(r2);
        if dir.is_empty() {
            let lines: Vec<String> = self
                .pathdirs
                .iter()
                .map(|(a, b)| format!("  #pathdir {{{}}} {{{}}}", a, b))
                .collect();
            let joined = lines.join("\r\n");
            self.output(&format!("{}\r\n", joined));
            return;
        }
        if rev.is_empty() {
            self.info("usage: #pathdir {dir} {reversed dir}");
            return;
        }
        self.pathdirs.insert(dir.clone(), rev.clone());
        self.info(&format!("ok. pathdir {{{}}} reverses to {{{}}}", dir, rev));
    }

    // ---- session / config / io ------------------------------------------

    fn cmd_session(&mut self, rest: &str, depth: u32) {
        let (name, r2) = get_arg(rest);
        let (host, r3) = get_arg(r2);
        let (port_s, _) = get_arg(r3);
        if name.is_empty() {
            if self.connected() {
                let msg = format!("connected to {}:{}", self.host, self.port);
                self.info(&msg);
            } else {
                self.info("no session. usage: #session {name} {host} {port}");
            }
            return;
        }
        if host.is_empty() {
            self.info("usage: #session {name} {host} {port}");
            return;
        }
        let host = self.subst(&host, depth);
        let port_s = self.subst(&port_s, depth);
        let port: u16 = match port_s.parse() {
            Ok(p) => p,
            Err(_) => {
                self.info(&format!("'{}' is not a port number", port_s));
                return;
            }
        };
        self.connect(&host, port);
    }

    fn cmd_ssl(&mut self, rest: &str, depth: u32) {
        let (_name, r2) = get_arg(rest);
        let (host, r3) = get_arg(r2);
        let (port_s, _) = get_arg(r3);
        if host.is_empty() {
            self.info("usage: #ssl {name} {host} {port} — telnet over TLS");
            return;
        }
        let host = self.subst(&host, depth);
        let port_s = self.subst(&port_s, depth);
        let port: u16 = if port_s.is_empty() {
            2324
        } else {
            match port_s.parse() {
                Ok(p) => p,
                Err(_) => {
                    self.info(&format!("'{}' is not a port number", port_s));
                    return;
                }
            }
        };
        self.connect_tls(&host, port);
    }

    fn cmd_run(&mut self, rest: &str, depth: u32) {
        let (name, r2) = get_arg(rest);
        let command = get_tail(r2);
        if name.is_empty() || command.is_empty() {
            self.info("usage: #run {name} {shell command} — e.g. #run {mud} {ssh -T play@host}");
            return;
        }
        let command = self.subst(&command, depth);
        self.connect_pipe(&name, &command);
    }

    fn cmd_config(&mut self, rest: &str) {
        let (opt, r2) = get_arg(rest);
        let val = get_tail(r2);
        let on = val.eq_ignore_ascii_case("on");
        match opt.to_lowercase().replace('_', " ").as_str() {
            "" => {
                let msg = format!(
                    "config: speedwalk {}, echo {}, verbatim {}, repeat char {}, packet patch {}",
                    onoff(self.speedwalk_on),
                    onoff(self.echo_on),
                    onoff(self.verbatim_on),
                    self.repeat_char,
                    self.packet_patch.as_secs_f64(),
                );
                self.info(&msg);
            }
            "speedwalk" => {
                self.speedwalk_on = on;
                self.info(&format!("ok. speedwalk is {}", onoff(on)));
            }
            "echo" => {
                self.echo_on = on;
                self.info(&format!("ok. echo is {}", onoff(on)));
            }
            "verbatim" => {
                self.verbatim_on = on;
                self.info(&format!("ok. verbatim is {}", onoff(on)));
            }
            "repeat char" => {
                if let Some(c) = val.chars().next() {
                    self.repeat_char = c;
                    if let Ui::Split(ui) = &mut self.ui {
                        ui.repeat_char = c;
                    }
                    self.info(&format!("ok. repeat char is {}", c));
                } else {
                    self.info("usage: #config {repeat char} {character}");
                }
            }
            "packet patch" => match val.trim().parse::<f64>() {
                Ok(s) if (0.0..=10.0).contains(&s) => {
                    self.packet_patch = Duration::from_secs_f64(s);
                    self.info(&format!("ok. packet patch is {}s", s));
                }
                _ => self.info("usage: #config {packet patch} {seconds, 0..10}"),
            },
            other => self.info(&format!(
                "unknown config option '{}' (speedwalk echo verbatim {{repeat char}} {{packet patch}})",
                other
            )),
        }
    }

    pub fn cmd_read(&mut self, rest: &str, depth: u32) {
        let path = get_tail(rest);
        if path.is_empty() {
            self.info("usage: #read {file}");
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let mut count = 0;
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let _ = self.run_input(line, depth + 1);
                    count += 1;
                }
                self.info(&format!("read {} commands from {}", count, path));
            }
            Err(e) => self.info(&format!("cannot read {}: {}", path, e)),
        }
    }

    fn cmd_write(&mut self, rest: &str) {
        let path = get_tail(rest);
        if path.is_empty() {
            self.info("usage: #write {file}");
            return;
        }
        let mut out = String::new();
        out.push_str("#nop -- written by judytin --\n");
        if self.speedwalk_on {
            out.push_str("#config speedwalk on\n");
        }
        if !self.echo_on {
            out.push_str("#config echo off\n");
        }
        if self.verbatim_on {
            out.push_str("#config verbatim on\n");
        }
        for (k, v) in &self.vars {
            out.push_str(&format!("#variable {{{}}} {{{}}}\n", k, v));
        }
        for (k, v) in &self.functions {
            out.push_str(&format!("#function {{{}}} {{{}}}\n", k, v));
        }
        for (k, v) in &self.aliases {
            out.push_str(&format!("#alias {{{}}} {{{}}}\n", k, v));
        }
        for (k, t) in &self.actions {
            out.push_str(&format!("#action {{{}}} {{{}}}\n", k, t.body));
        }
        for (k, v) in &self.subs {
            out.push_str(&format!("#substitute {{{}}} {{{}}}\n", k, v));
        }
        for (k, v) in &self.highlights {
            out.push_str(&format!("#highlight {{{}}} {{{}}}\n", k, v));
        }
        for g in &self.gags {
            out.push_str(&format!("#gag {{{}}}\n", g));
        }
        for (k, v) in &self.macros {
            out.push_str(&format!("#macro {{{}}} {{{}}}\n", k, v));
        }
        for (k, v) in &self.events {
            out.push_str(&format!("#event {{{}}} {{{}}}\n", k, v));
        }
        for t in &self.tabs {
            out.push_str(&format!("#tab {{{}}}\n", t));
        }
        for (k, t) in &self.tickers {
            out.push_str(&format!(
                "#ticker {{{}}} {{{}}} {{{}}}\n",
                k,
                t.body,
                t.interval.as_secs_f64()
            ));
        }
        match std::fs::write(&path, out) {
            Ok(_) => self.info(&format!("settings written to {}", path)),
            Err(e) => self.info(&format!("cannot write {}: {}", path, e)),
        }
    }

    fn cmd_textin(&mut self, rest: &str) {
        let path = get_tail(rest);
        if path.is_empty() {
            self.info("usage: #textin {file}");
            return;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let mut n = 0;
                for line in content.lines() {
                    self.send_line(line);
                    n += 1;
                }
                self.info(&format!("sent {} lines from {}", n, path));
            }
            Err(e) => self.info(&format!("cannot read {}: {}", path, e)),
        }
    }

    fn cmd_system(&mut self, rest: &str, depth: u32) {
        let cmd = self.subst(&get_tail(rest), depth);
        if cmd.is_empty() {
            self.info("usage: #system {shell command}");
            return;
        }
        match std::process::Command::new("sh").arg("-c").arg(&cmd).output() {
            Ok(out) => {
                for chunk in [&out.stdout, &out.stderr] {
                    let text = String::from_utf8_lossy(chunk);
                    for line in text.lines() {
                        self.output(&format!("{}\r\n", line));
                    }
                }
                if !out.status.success() {
                    self.info(&format!("#system exited with {}", out.status));
                }
            }
            Err(e) => self.info(&format!("#system: {}", e)),
        }
    }

    fn cmd_help(&mut self) {
        let help = "\
\x1b[1mjudytin\x1b[0m — a tiny TinTin++ for judymud\r
\r
  commands start with #, separate commands with ; and group arguments with {}\r
  %1..%99 are wildcards/arguments, $name inserts a variable, @func{} calls\r
  #5 {commands} repeats 5 times, ! recalls history, tab completes words\r
\r
  \x1b[1msession\x1b[0m   #session {name} {host} {port}, #zap, #end\r
            #ssl {name} {host} {port} telnet-over-TLS (pin kept in ~/.judytin_known_hosts)\r
            #run {name} {ssh -T you@host} any command as the byte pipe\r
  \x1b[1mtriggers\x1b[0m  #alias #action #highlight #substitute #gag #variable #function\r
            #macro {f5} {...}  #event {SESSION CONNECTED} {...}  #tab {word}\r
            each has an #un... remover; bare command lists definitions\r
  \x1b[1mflow\x1b[0m      #if {expr} {then} {else}, #elseif, #else, #switch/#case/#default\r
            #loop {1} {10} {i} {...}, #while, #foreach {a;b} {x} {...}\r
            #break #continue #return, #math {var} {expr}, #local, #format\r
  \x1b[1mtimers\x1b[0m    #ticker {name} {cmds} {secs}, #delay {secs} {cmds}\r
  \x1b[1mscreen\x1b[0m    PgUp/PgDn scrollback, #buffer {up|down|home|end|find}, #grep\r
            #history, #showme, #echo {fmt} {args}, #bell, #split\r
  \x1b[1morganize\x1b[0m  #class {x} {open|close|clear|kill|list|write}, #kill, #info\r
            #message {kind} {off}, #line {gag|oneshot|quiet|verbatim}\r
  \x1b[1mworld\x1b[0m     #config speedwalk on (then 3n2e or nesw walks), #path, #pathdir\r
            #send {raw}, #cr, #textin {file}, #system {cmd}, #log {append} {f}\r
  \x1b[1mfiles\x1b[0m     #read {file}, #write {file}, ~/.judytinrc at startup\r
\r
  ctrl-d on an empty line quits, ctrl-l redraws, #commands lists everything\r
\r
  \x1b[2mjudymud quickstart: 'guest <name>' at the door; judymud.tin saves\r
  the resume command in $resume — rk shows it, res re-sends it\x1b[0m\r
";
        self.output(help);
    }
}

fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn zip_speedwalk(path: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut run: Option<(char, usize)> = None;
    let flush = |out: &mut String, run: &mut Option<(char, usize)>| {
        if let Some((c, n)) = run.take() {
            if n > 1 {
                out.push_str(&n.to_string());
            }
            out.push(c);
        }
    };
    for (fwd, _) in path {
        let letter = match fwd.as_str() {
            "n" | "north" => Some('n'),
            "s" | "south" => Some('s'),
            "e" | "east" => Some('e'),
            "w" | "west" => Some('w'),
            "u" | "up" => Some('u'),
            "d" | "down" => Some('d'),
            _ => None,
        };
        match letter {
            Some(l) => match &mut run {
                Some((c, n)) if *c == l => *n += 1,
                _ => {
                    flush(&mut out, &mut run);
                    run = Some((l, 1));
                }
            },
            None => {
                flush(&mut out, &mut run);
                out.push('{');
                out.push_str(fwd);
                out.push('}');
            }
        }
    }
    flush(&mut out, &mut run);
    out
}
