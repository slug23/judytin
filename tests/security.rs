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
    // An empty HOME, so ~/.judytinrc cannot arm anything an attack test is
    // about to rely on being off. The suite must measure judytin, not whoever
    // is running it.
    let empty = std::env::temp_dir().join(format!("judytin-nohome-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_judytin"))
        .args(["--dumb", "127.0.0.1", &port.to_string()])
        .env("HOME", &empty)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(90));
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

#[test]
fn a_trigger_cannot_make_reconnect_respawn_a_process() {
    // #reconnect returns to the last session. When that session is a pipe,
    // returning to it means spawning a process again — and while the command
    // line is the player's own and beyond the server's reach, *when* it runs
    // would be the server's to choose if a trigger could fire this. "The mud
    // decides when judytin spawns processes" is the shape the gate refuses, so
    // a pipe recipe is gated exactly like #run.
    //
    // The pipe here is both transport and attacker: what a subprocess prints is
    // server text like any other.
    let m = marker("respawn");
    let port = hostile_server(vec![]);
    let out = run(
        port,
        &format!(
            "#zap\n\
             #action {{spawn now}} {{#reconnect}}\n\
             #run {{probe}} {{sh -c 'echo ran >> {}; echo spawn now; sleep 3'}}\n\
             #delay {{2}} {{#end}}\n",
            m.display()
        ),
    );
    let ran = std::fs::read_to_string(&m).unwrap_or_default();
    let _ = std::fs::remove_file(&m);
    assert_eq!(
        ran.lines().count(),
        1,
        "the process ran {} times — a trigger re-spawned it through #reconnect:\n{}",
        ran.lines().count(),
        out.stdout
    );
    assert!(
        out.says("#reconnect refused"),
        "expected the gate to say why it refused:\n{}",
        out.stdout
    );
}

#[test]
fn running_something_in_every_session_does_not_launder_the_gate() {
    // `#all` and `#name` put a command into another session's focus, which is
    // a new layer between a trigger and what it runs. If the gate lived in the
    // focus rather than in the execution, `#all {#system ...}` would be a way
    // to step over it — and the same shape as the timer laundering above, so
    // it is kept as a regression the moment the layer was added.
    let m = marker("allgate");
    let port = hostile_server(vec!["go now\r\n".to_string()]);
    let out = run(
        port,
        &format!(
            "#action {{go now}} {{#all {{#system touch {}}}}}\n\
             #delay {{2}} {{#end}}\n",
            m.display()
        ),
    );
    assert_not_created(&m, "#all ran a shell command for a trigger");
    assert!(out.says("refused"), "expected the gate to say why it refused:\n{}", out.stdout);
}

#[test]
fn a_trigger_cannot_spawn_a_process_by_spelling_run_differently() {
    // `#session {name} {ssh://you@host}` opens the same thing `#run` opens: a
    // program on this machine, with the mud on the far end of its pipe. The
    // gate is about the act, not the word, so giving `#session` a second way
    // to spell it must not give a trigger a way around the gate.
    //
    // A regression the moment `ssh://` was added, and the reason the pipe
    // check lives on the single path every opening command goes through.
    let port = hostile_server(vec!["spawn now\r\n".to_string()]);
    let out = run(
        port,
        "#action {spawn now} {#session {probe} {ssh://nobody@127.0.0.1:1}}\n\
         #delay {2} {#end}\n",
    );
    assert!(
        !out.did("running ssh"),
        "PROCESS SPAWNED BY THE SERVER: a trigger opened an ssh:// session:\n{}",
        out.stdout
    );
    assert!(
        out.says("refused"),
        "expected the gate to say why it refused:\n{}",
        out.stdout
    );
}

#[test]
fn a_trigger_may_still_reopen_a_socket() {
    // The gate is about touching the machine, not about reconnecting. A socket
    // session costs the server only the connection it just dropped, so a
    // trigger reopening one is not the thing being prevented — and refusing it
    // would make the gate look arbitrary.
    let port = hostile_server(vec!["come back\r\n".to_string()]);
    let out = run(
        port,
        "#action {come back} {#zap;#reconnect}\n#delay {2} {#end}\n",
    );
    assert!(
        !out.says("#reconnect refused"),
        "a socket reconnect was gated as if it touched the machine:\n{}",
        out.stdout
    );
}

#[test]
fn a_capture_cannot_close_the_subscript_it_landed_in() {
    // $var[key] made [ and ] syntax. A capture spliced into a subscript is
    // therefore in the same position a capture inside {braces} was before the
    // data discipline existed: close the bracket early and the remainder of
    // the line is read as script rather than as a key.
    let m = marker("subscript");
    let port = hostile_server(vec![format!(
        "x];#system touch {} ;#nop [ arrives\r\n",
        m.display()
    )]);
    let out = run(
        port,
        "#variable {tbl[x]} {harmless}\n\
         #action {%1 arrives} {#showme $tbl[%1]}\n\
         #delay {2} {#end}\n",
    );
    assert_not_created(&m, "a `]` in a capture closed the subscript around it");
    // The trigger should still have run, printing the unresolved name as text.
    assert!(
        out.says("$tbl["),
        "the trigger did not fire at all, so this proves nothing:\n{}",
        out.stdout
    );
}

#[test]
fn a_capture_cannot_pick_which_entry_a_table_lookup_returns() {
    // Subtler than execution, and the reason $tbl[$key] resolves the key
    // before looking up rather than after: server text must not be able to
    // reach a *different* entry than the one the script named. Here the
    // trigger looks up tbl[safe]; the server tries to redirect it to
    // tbl[secret] by closing and reopening the subscript.
    let port = hostile_server(vec!["secret] $tbl[ arrives\r\n".to_string()]);
    let out = run(
        port,
        "#variable {tbl[safe]} {public-value}\n\
         #variable {tbl[secret]} {PRIVATE-VALUE}\n\
         #action {%1 arrives} {#showme got $tbl[safe]}\n\
         #delay {2} {#end}\n",
    );
    // Compared against the showme output, not the whole transcript: setting the
    // variable echoes its value, so a bare search would match the setup.
    assert!(
        !out.did("got PRIVATE-VALUE"),
        "server text steered a table lookup to another entry:\n{}",
        out.stdout
    );
    assert!(out.did("got public-value"), "the lookup did not happen:\n{}", out.stdout);
}

#[test]
fn server_text_cannot_become_a_regex() {
    // {regex} in a pattern is now a compiled expression. A trigger that builds
    // another trigger from a capture therefore has a new way to go wrong: if
    // the capture reached `compile` unescaped, a server could install a
    // pattern of its own choosing — `{.*}` matches every line, which turns one
    // trigger into a trigger on everything.
    let port = hostile_server(vec![
        "{.*} arrives\r\n".to_string(),
        "some unrelated line\r\n".to_string(),
    ]);
    let out = run(
        port,
        "#action {%1 arrives} {#action {%1} {#showme PWNED}}\n\
         #delay {2} {#end}\n",
    );
    // Neither the echo of the command nor the "#ok." that confirms it counts:
    // both quote the body back, marker and all. Only the trigger actually
    // running prints the marker on a line of its own.
    let fired = out
        .stdout
        .lines()
        .any(|l| l.contains("PWNED") && !l.contains(">> ") && !l.contains("#ok."));
    assert!(
        !fired,
        "a capture became a live regex and matched everything:\n{}",
        out.stdout
    );
    // And prove the trigger was really installed, or this proves nothing: the
    // pattern is stored with its escapes, which is what keeps it literal.
    assert!(
        out.says(r"\{.*\}"),
        "the nested action was never created:\n{}",
        out.stdout
    );
}

#[test]
fn a_regex_trigger_cannot_be_made_to_hang() {
    // The subject is a stranger's line, so the classic catastrophic-
    // backtracking shape is theirs to send. Two defences: the regex crate is
    // linear in the subject, and the match budget charges for the length
    // scanned rather than per call — without the second, this took three
    // minutes on a line the server picked.
    let flood = "a".repeat(60_000);
    let port = hostile_server(vec![format!("{flood}\r\n"), format!("{flood}\r\n")]);
    let out = run(
        port,
        "#action {{(a+)+$}b} {#showme never}\n\
         #action {{a*a*a*a*a*c}} {#showme never}\n\
         #delay {3} {#end}\n",
    );
    assert!(!out.says("panicked"), "crashed on a regex flood:\n{}", out.stdout);
    assert_eq!(
        out.status,
        Some(0),
        "the event loop stopped servicing timers while matching:\n{}",
        out.stdout
    );
}

#[test]
fn a_capture_stored_in_a_list_cannot_detonate_later() {
    // Same laundering shape as the function-call attack, one container along:
    // the trigger parks server text in a list, and a later #list operation
    // reads it back out. Items are stored escaped and every step that touches
    // one — collapse, explode, get — has to keep it that way.
    let m = marker("listitem");
    let port = hostile_server(vec![format!(
        "loot is gold;#system touch {} #\r\n",
        m.display()
    )]);
    run(
        port,
        "#action {loot is %1} {#list {bag} {add} {%1}}\n\
         #delay {1} {#list {bag} {collapse} {;}}\n\
         #delay {2} {#list {bag} {explode} {;}}\n\
         #delay {2.5} {#list {bag} {get} {1} {out}}\n\
         #delay {3.5} {#end}\n",
    );
    assert_not_created(&m, "server text in a list item became a command");
}

#[test]
fn an_escaped_separator_does_not_split_a_list_item() {
    // Not execution: an item quietly becoming two items. The server sends text
    // containing the separator the player is about to explode on, and if the
    // split ignored escaping it would cut the server's text into pieces the
    // script never asked for — and change what every later index means.
    let port = hostile_server(vec!["loot is one;two\r\n".to_string()]);
    // The capture goes into the scalar $bag, which is what explode reads. Its
    // `;` arrives escaped, so the split must not see it as a boundary.
    //
    // The count is read from explode's own report rather than by scheduling a
    // #size and a #showme after it: each extra step is another sub-second
    // delay that has to land before the mock hangs up, and under a busy
    // machine they stop landing. One step, one assertion.
    let out = run(
        port,
        "#action {loot is %1} {#variable {bag} {%1}}\n\
         #delay {0.4} {#list {bag} {explode} {;}}\n\
         #delay {0.8} {#end}\n",
    );
    assert!(
        out.did("list {bag} has 1 item(s)"),
        "explode did not run, or split one item into several:\n{}",
        out.stdout
    );
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
    let out = run(
        port,
        "#action {%1 tells you %2} {say hi %1}\n#delay {3} {#end}\n",
    );
    assert!(!out.says("panicked"), "crashed on a newline-less flood:\n{}", out.stdout);
    // Freezing is proved by the timer never firing, not by a stopwatch. `run`
    // kills the client after 20 seconds, so a clean exit means the event loop
    // was still servicing #delay while the flood arrived — which is the actual
    // claim. Timing the wall clock instead measured whatever else the machine
    // was doing: this test swung between 3 and 15 seconds on an unchanged
    // client, and failed whenever the suite grew.
    assert_eq!(
        out.status,
        Some(0),
        "the event loop stopped servicing timers under a flood:\n{}",
        out.stdout
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

// ---- prompt triggers ----------------------------------------------------

#[test]
fn a_prompt_capture_cannot_become_a_command() {
    // #prompt is a second door for server text to enter a script, and the
    // prompt is the least-watched line on the screen. A payload parked in an
    // unterminated prompt must be as inert as one in a finished line.
    let m = marker("promptcap");
    let port = hostile_server(vec![format!(
        "\r\n30;#system touch {} #/56hp 12/30m 0g> ",
        m.display()
    )]);
    let out = run(
        port,
        "#prompt {%1/%2hp} {#variable {hp} {%1};#showme vitals %1}\n#delay {2} {#end}\n",
    );
    assert_not_created(&m, "a `;` in a prompt capture started a new command");
    assert!(out.did("vitals"), "prompt trigger did not run at all:\n{}", out.stdout);
}

#[test]
fn a_prompt_trigger_cannot_touch_the_machine() {
    // The prompt arrives unasked, on the server's schedule, and it is the one
    // line a player never reads. A #prompt body is server-driven for the same
    // reason an #action body is, and the gate must cover it.
    let m = marker("promptexec");
    let port = hostile_server(vec!["\r\n30/56hp 12/30m 0g> ".to_string()]);
    let out = run(
        port,
        &format!(
            "#prompt {{%1/%2hp}} {{#system touch {}}}\n#delay {{2}} {{#end}}\n",
            m.display()
        ),
    );
    assert_not_created(&m, "a #prompt body ran a shell command");
    assert!(
        out.did("refused") || out.did("trigger"),
        "the refusal was silent, which teaches nobody:\n{}",
        out.stdout
    );
}

#[test]
fn a_variable_cannot_name_a_command() {
    // #$var picks which session runs something. It must never pick *what*
    // runs: variables can hold server text, so allowing an expansion to
    // resolve to a command name would let a MUD choose #system by getting a
    // trigger to store the word.
    let m = marker("varcmd");
    let port = hostile_server(vec![format!("the word is system\r\n")]);
    let out = run(
        port,
        &format!(
            "#action {{the word is %1}} {{#variable {{picked}} {{%1}}}}\n\
             #delay {{1.2}} {{#$picked {{touch {}}}}}\n\
             #delay {{2.5}} {{#end}}\n",
            m.display()
        ),
    );
    assert_not_created(&m, "a variable expanded into a command name");
    assert!(
        out.did("no session named"),
        "the refusal was silent:\n{}",
        out.stdout
    );
}

#[test]
fn server_text_shaped_like_a_function_call_is_not_reported_as_one() {
    // judytin now complains about @name{} naming no function. That must not
    // become a way for a MUD to print client diagnostics, or worse to probe
    // which functions a player has defined by watching what is complained
    // about. `@` is in META, so server text arrives escaped and never reaches
    // the call parser at all.
    let port = hostile_server(vec!["Bob says '@secretfn{} @alsonope{}'\r\n".to_string()]);
    let out = run(
        port,
        "#action {%1 says %2} {#variable {heard} {%2}}\n#delay {1.5} {#end}\n",
    );
    assert!(
        !out.did("no function"),
        "a server made judytin report on its own function table:\n{}",
        out.stdout
    );
}

#[test]
fn a_filename_from_a_variable_still_cannot_be_reached_by_a_trigger() {
    // #read, #write, #log and #textin now substitute their filename, so a
    // variable can name a file. That must not become a way for a server to
    // name one: a trigger stores server text in a variable and then a second
    // trigger tries to write there.
    let m = marker("filevar");
    let port = hostile_server(vec![format!("the path is {}\r\n", m.display())]);
    let out = run(
        port,
        "#action {the path is %1} {#variable {p} {%1};#write $p;#log append $p;#textin $p}\n\
         #delay {2} {#end}\n",
    );
    assert_not_created(&m, "a trigger wrote to a filename it learned from the server");
    assert!(
        out.did("refused") || out.did("trigger"),
        "the refusal was silent:\n{}",
        out.stdout
    );
}

#[test]
fn a_trigger_answering_its_own_echo_is_bounded() {
    // judytin-s66: a login trigger answers "By what name...", the server
    // rejects the answer and asks again, and nothing anywhere stops the
    // cycle. Reusing a taken name once produced roughly 350,000 round trips
    // and a 354,740-line transcript in about forty seconds, and stopped only
    // because the server reset the connection.
    //
    // judytin was doing exactly what it was told, across the network, where
    // its own recursion limits cannot see it — and hammering a stranger's
    // machine while doing it. The ceiling is on lines a trigger may send in a
    // second, so a busy script is unaffected and a loop is not.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(0u32));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else { return };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
        // Held back so the trigger is certainly in place before the door
        // speaks. Startup reads the script before connecting now, so this is
        // determinism rather than a workaround — but a test of a runaway loop
        // that quietly never starts the loop is worse than no test, and this
        // one did exactly that until the pause was added.
        std::thread::sleep(Duration::from_millis(700));
        let _ = sock.write_all(b"By what name do you wish to be known?\r\n");
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while std::time::Instant::now() < deadline {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let hits = buf[..n].iter().filter(|&&b| b == b'\n').count() as u32;
                    *s2.lock().unwrap() += hits;
                    // Refuse, and ask again. This is the whole attack.
                    for _ in 0..hits {
                        if sock
                            .write_all(b"That name is taken.\r\nBy what name do you wish to be known?\r\n")
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    });
    let out = run(
        port,
        "#action {By what name do you wish to be known} {guest bob warrior}\n\
         #delay {3.2} {#end}\n",
    );
    let n = *seen.lock().unwrap();
    // Two and a half seconds at the ceiling is a few hundred, not a hundred
    // thousand. The bound is what matters, not the exact number.
    assert!(
        n < 1000,
        "trigger loop was not bounded: server saw {} answers\n{}",
        n,
        out.stdout
    );
    assert!(
        out.did("sent") && out.did("lines in a second"),
        "judytin throttled silently, which teaches nobody:\n{}",
        out.stdout
    );
}

#[test]
fn a_comment_never_reaches_the_server() {
    // A `;` in a #nop used to end the comment, and the rest of the prose ran
    // as a command — which, connected, means it was sent to the MUD. Silent,
    // because a nonsense game command produces nothing much. This is not an
    // attack a server can mount, but it is the client leaking the player's
    // own notes to one, which belongs in the same suite.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let h2 = heard.clone();
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else { return };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
        let _ = sock.write_all(b"Welcome.\r\n");
        let mut buf = [0u8; 4096];
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 {
                break;
            }
            h2.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    run(
        port,
        "#nop the leader walks; everyone else follows it home\n\
         #nop a note with; several; semicolons in it\n\
         look\n\
         #delay {1.5} {#end}\n",
    );
    let said = heard.lock().unwrap().clone();
    assert!(
        !said.contains("everyone else follows"),
        "a comment was sent to the server: {:?}",
        said
    );
    assert!(!said.contains("several"), "a comment was sent to the server: {:?}", said);
    // The real command on the next line still went, so nothing was swallowed.
    assert!(said.contains("look"), "the command after the comments was lost: {:?}", said);
}
