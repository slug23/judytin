//! Attack suite.
//!
//! Every test here is a hostile MUD server. They exist because a MUD client
//! runs a scripting language over text a stranger controls, which is the
//! same shape as SQL injection and deserves the same suspicion.
//!
//! Each test states the attack, not just the assertion, so that a future
//! change which reopens a hole fails with a description of what it let in.
//! Several of these were live remote-code-execution or remote-crash bugs;
//! they are kept as regressions forever.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

/// A scripted server: sends `lines` (each already \r\n-terminated or not),
/// then keeps the socket open briefly so the client can react.
fn hostile_server(lines: Vec<String>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        let _ = sock.write_all(b"Welcome to hostilemud\r\n> ");
        for line in lines {
            std::thread::sleep(Duration::from_millis(60));
            if sock.write_all(line.as_bytes()).is_err() {
                return;
            }
        }
        // Drain whatever the client says back, so it never blocks on write.
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1200)));
        let mut buf = [0u8; 4096];
        let mut seen = Vec::new();
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
        }
    });
    port
}

struct Run {
    stdout: String,
    status: Option<i32>,
}

impl Run {
    fn says(&self, needle: &str) -> bool {
        self.stdout.contains(needle)
    }

    /// True if `needle` appears on a line that is *not* the client echoing
    /// back a command it was given. Without this a test can pass or fail on
    /// the echo of its own script rather than on what actually happened.
    fn did(&self, needle: &str) -> bool {
        self.stdout
            .lines()
            .filter(|line| !line.contains(">> "))
            .any(|line| line.contains(needle))
    }
}

/// Run the real binary against a port, feeding it `script` on stdin.
fn run(port: u16, script: &str) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_judytin"))
        .args(["--dumb", "127.0.0.1", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    stdout.push_str(&String::from_utf8_lossy(&out.stderr));
    Run { stdout, status: out.status.code() }
}

/// A marker path the payloads try to create. Its absence is the proof.
fn marker(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("judytin-attack-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn assert_not_created(path: &std::path::Path, what: &str) {
    let created = path.exists();
    let _ = std::fs::remove_file(path);
    assert!(!created, "ARBITRARY CODE EXECUTION: {what}");
}

// ---- injection ---------------------------------------------------------

#[test]
fn capture_carrying_a_separator_cannot_become_a_command() {
    // The classic: %1 captures text containing `;#system …`. Before the data
    // discipline this created the file.
    let m = marker("sep");
    let port = hostile_server(vec![format!(
        "Bob;#system touch {} # tells you hello\r\n",
        m.display()
    )]);
    let out = run(
        port,
        "#action {%1 tells you %2} {tell %1 got it}\n#delay {2} {#end}\n",
    );
    assert_not_created(&m, "a `;` in a trigger capture started a new command");
    // The payload should have gone out as ordinary text instead.
    assert!(out.says("got it") || out.says("tell"), "trigger did not run at all:\n{}", out.stdout);
}

#[test]
fn capture_carrying_a_brace_cannot_escape_its_group() {
    // The shape that made the shipped judymud.tin exploitable: the capture
    // sits inside {braces}, so the payload closes the group early with `}`.
    let m = marker("brace");
    let port = hostile_server(vec![format!(
        "`resume A x}};#system touch {} ;#nop {{`\r\n",
        m.display()
    )]);
    run(
        port,
        "#action {`resume %1 %2`} {#variable {resume} {resume %1 %2};#showme {saved}}\n\
         #delay {2} {#end}\n",
    );
    assert_not_created(&m, "a `}` in a capture closed its brace group");
}

#[test]
fn received_line_event_cannot_execute_the_line() {
    // Worst case: no trigger pattern needed. #event {RECEIVED LINE} hands
    // %1 the entire plain line, so every line is a candidate payload.
    let m = marker("event");
    let port = hostile_server(vec![format!(
        "x;#system touch {} #\r\n",
        m.display()
    )]);
    run(
        port,
        "#event {RECEIVED LINE} {#variable {last} {%1}}\n#delay {2} {#end}\n",
    );
    assert_not_created(&m, "a RECEIVED LINE event executed the server's line");
}

#[test]
fn a_function_call_cannot_detonate_stored_server_text() {
    // Laundering: the trigger stores the payload harmlessly in a variable,
    // and a later @function{$var} call re-parses it. The trigger looks safe
    // in isolation; the explosion happens somewhere else entirely.
    let m = marker("func");
    let port = hostile_server(vec![format!(
        "mob is bob;#system touch {} #\r\n",
        m.display()
    )]);
    run(
        port,
        "#action {mob is %1} {#variable {mob} {%1}}\n\
         #function {greet} {say hello %0}\n\
         #delay {1} {@greet{$mob}}\n\
         #delay {3} {#end}\n",
    );
    assert_not_created(&m, "a function call re-parsed stored server text");
}

#[test]
fn a_timer_created_by_a_trigger_cannot_launder_the_restriction() {
    // Deferral attack: the trigger cannot run #system, so it schedules one
    // for a moment later, hoping the clock washes off the taint.
    let m = marker("delay");
    let port = hostile_server(vec!["the bell rings\r\n".to_string()]);
    let out = run(
        port,
        &format!(
            "#action {{the bell rings}} {{#delay {{0.2}} {{#system touch {}}}}}\n\
             #delay {{2}} {{#end}}\n",
            m.display()
        ),
    );
    assert_not_created(&m, "a #delay scheduled by a trigger escaped the gate");
    assert!(
        out.says("refused"),
        "expected the gate to say why it refused:\n{}",
        out.stdout
    );
}

#[test]
fn server_text_cannot_steer_a_scripted_decision() {
    // Not code execution — the branches are the user's own — but a hostile
    // server closing the quote in `#if {"$mob" == "dragon"}` could make any
    // scripted guard take the branch it wants.
    let port = hostile_server(vec!["mob is x\" == \"x\" || \"\r\n".to_string()]);
    let out = run(
        port,
        "#action {mob is %1} {#variable {mob} {%1}}\n\
         #delay {1} {#if {\"$mob\" == \"dragon\"} {#showme STEERED} {#showme SAFE}}\n\
         #delay {3} {#end}\n",
    );
    assert!(
        !out.did("STEERED"),
        "EXPRESSION INJECTION: server text closed its quote and flipped the guard:\n{}",
        out.stdout
    );
    assert!(out.did("SAFE"), "the guard did not evaluate at all:\n{}", out.stdout);
}

#[test]
fn the_gate_still_lets_the_user_run_things_themselves() {
    // The restriction must be about *who caused it*, not a blanket ban:
    // a command the user types stays fully powerful.
    let m = marker("user");
    let port = hostile_server(vec!["nothing happens\r\n".to_string()]);
    let out = run(port, &format!("#system touch {}\n#delay {{1}} {{#end}}\n", m.display()));
    let created = m.exists();
    let _ = std::fs::remove_file(&m);
    assert!(created, "a user-typed #system was wrongly refused:\n{}", out.stdout);
}

// ---- crashes and exhaustion -------------------------------------------

#[test]
fn an_escape_before_a_multibyte_character_does_not_crash() {
    // Needs no triggers and no configuration: ESC followed by a multi-byte
    // character used to slice mid-character and panic an idle client.
    let port = hostile_server(vec!["hello \x1bé world\r\n".to_string()]);
    let out = run(port, "#delay {2} {#end}\n");
    assert!(!out.says("panicked"), "REMOTE CRASH on ESC + non-ASCII:\n{}", out.stdout);
    assert_eq!(out.status, Some(0), "client did not exit cleanly:\n{}", out.stdout);
}

#[test]
fn a_highlight_next_to_a_multibyte_character_does_not_crash() {
    // The scan resumed one byte past a match, which lands inside the next
    // character when it is multi-byte. An em-dash in normal MUD prose is
    // enough, so this fired in ordinary play, not only under attack.
    let port = hostile_server(vec!["resume keyé keep it safe\r\n".to_string()]);
    let out = run(port, "#highlight {resume key} {light red}\n#delay {2} {#end}\n");
    assert!(!out.says("panicked"), "REMOTE CRASH on highlight + non-ASCII:\n{}", out.stdout);
    assert_eq!(out.status, Some(0), "client did not exit cleanly:\n{}", out.stdout);
}

#[test]
fn a_substitution_next_to_a_multibyte_character_does_not_crash() {
    let port = hostile_server(vec!["the orcé snarls\r\n".to_string()]);
    let out = run(port, "#substitute {orc} {ORC}\n#delay {2} {#end}\n");
    assert!(!out.says("panicked"), "REMOTE CRASH on substitute + non-ASCII:\n{}", out.stdout);
    assert_eq!(out.status, Some(0));
}

#[test]
fn a_line_that_never_ends_does_not_exhaust_memory_or_time() {
    // A server that sends no newline once grew the line buffer without
    // limit, and fed the trigger matcher a line long enough to freeze the
    // single-threaded event loop.
    let flood = "A".repeat(400_000);
    let port = hostile_server(vec![flood.clone(), flood]);
    let started = std::time::Instant::now();
    let out = run(
        port,
        "#action {%1 tells you %2} {say hi %1}\n#delay {3} {#end}\n",
    );
    let elapsed = started.elapsed();
    assert!(!out.says("panicked"), "crashed on a newline-less flood:\n{}", out.stdout);
    assert!(
        elapsed < Duration::from_secs(15),
        "client froze on a newline-less flood: {:?}",
        elapsed
    );
}

#[test]
fn a_deeply_nested_expression_does_not_abort_the_process() {
    // A stack overflow aborts without unwinding, so the terminal would be
    // left in raw mode with a mangled scroll region — worse than a panic.
    let nested = format!("mob is {}1{}", "(".repeat(20_000), ")".repeat(20_000));
    let port = hostile_server(vec![format!("{nested}\r\n")]);
    let out = run(
        port,
        "#action {mob is %1} {#variable {mob} {%1}}\n\
         #delay {1} {#if {$mob} {#showme yes} {#showme no}}\n\
         #delay {3} {#end}\n",
    );
    assert!(
        !out.says("stack overflow"),
        "STACK OVERFLOW from server-supplied expression:\n{}",
        out.stdout
    );
    assert_ne!(out.status, Some(134), "process aborted:\n{}", out.stdout);
}
