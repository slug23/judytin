//! judytin — a tiny TinTin++-style MUD client, built for judymud.

mod ansi;
mod app;
mod commands;
mod data;
mod expr;
mod fmt;
mod net;
mod pattern;
mod script;
mod telnet;
mod ui;

use std::io::BufRead;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyEventKind};
use crossterm::tty::IsTty;

use app::{App, Ev, Ui};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 2323;

struct Args {
    host: String,
    port: Option<u16>,
    scripts: Vec<String>,
    dumb: bool,
    offline: bool,
    tls: bool,
    ssh: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        host: DEFAULT_HOST.to_string(),
        port: None,
        scripts: Vec::new(),
        dumb: false,
        offline: false,
        tls: false,
        ssh: None,
    };
    let mut positional: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!(
                    "judytin {} — a tiny TinTin++ for judymud\n\n\
                     usage: judytin [options] [host] [port]\n\n\
                     defaults to {}:{} (judymud's telnet door)\n\n\
                     options:\n\
                     \x20 -r <file>       read a script file at startup (repeatable)\n\
                     \x20 --tls           connect with TLS (defaults to port 2324; the\n\
                     \x20                 server cert is pinned in ~/.judytin_known_hosts)\n\
                     \x20 --ssh <dest>    connect through the system ssh, e.g.\n\
                     \x20                 --ssh grib@mudhost (port 2322 unless you say\n\
                     \x20                 otherwise) — your ssh key is your character\n\
                     \x20 --dumb          plain line mode, no split screen (auto when piped)\n\
                     \x20 --offline       don't connect at startup; use #session later\n\
                     \x20 -h, --help      this text\n\
                     \x20 -V              version\n\n\
                     also reads ~/.judytinrc at startup if it exists.\n\
                     inside the client, #help lists the commands.",
                    env!("CARGO_PKG_VERSION"),
                    DEFAULT_HOST,
                    DEFAULT_PORT
                );
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("judytin {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-r" => {
                let f = it.next().ok_or("-r needs a file argument")?;
                args.scripts.push(f);
            }
            "--dumb" => args.dumb = true,
            "--offline" => args.offline = true,
            "--tls" => args.tls = true,
            "--ssh" => {
                let dest = it.next().ok_or("--ssh needs a destination (user@host[:port])")?;
                args.ssh = Some(dest);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{}' (try --help)", other));
            }
            other => positional.push(other.to_string()),
        }
    }
    if let Some(h) = positional.first() {
        args.host = h.clone();
    }
    if let Some(p) = positional.get(1) {
        args.port =
            Some(p.parse().map_err(|_| format!("'{}' is not a port number", p))?);
    }
    if positional.len() > 2 {
        return Err("too many arguments (try --help)".to_string());
    }
    Ok(args)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("judytin: {}", e);
            std::process::exit(2);
        }
    };

    let interactive = std::io::stdin().is_tty() && std::io::stdout().is_tty();
    let dumb = args.dumb || !interactive;

    let (tx, rx) = mpsc::channel::<Ev>();

    let ui = if dumb {
        Ui::Dumb
    } else {
        match ui::SplitUi::new() {
            Ok(u) => Ui::Split(u),
            Err(e) => {
                eprintln!("judytin: cannot set up terminal: {}", e);
                std::process::exit(1);
            }
        }
    };

    let mut app = App::new(ui, tx.clone());
    app.info(&format!(
        "judytin {} — a tiny TinTin++ for judymud. #help for commands.",
        env!("CARGO_PKG_VERSION")
    ));

    // startup scripts: ~/.judytinrc, then -r files in order
    if let Ok(home) = std::env::var("HOME") {
        let rc = format!("{}/.judytinrc", home);
        if std::path::Path::new(&rc).exists() {
            app.cmd_read(&rc, 0);
        }
    }
    for script in &args.scripts {
        app.cmd_read(script, 0);
    }

    if !args.offline {
        if let Some(dest) = &args.ssh {
            app.connect_ssh(dest);
        } else if args.tls {
            app.connect_tls(&args.host, args.port.unwrap_or(2324));
        } else {
            app.connect(&args.host, args.port.unwrap_or(DEFAULT_PORT));
        }
    }

    // input thread
    if dumb {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) => {
                        if tx.send(Ev::Line(l)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(Ev::StdinEof);
        });
    } else {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            match crossterm::event::read() {
                Ok(Event::Key(k)) => {
                    if k.kind != KeyEventKind::Release && tx.send(Ev::Key(k)).is_err() {
                        return;
                    }
                }
                Ok(Event::Resize(c, r)) => {
                    if tx.send(Ev::Resize(c, r)).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        });
    }

    // main event loop
    while !app.quit {
        let timeout = app
            .next_deadline()
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_secs(60));
        match rx.recv_timeout(timeout) {
            Ok(ev) => app.on_event(ev),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        app.tick();
    }
}
