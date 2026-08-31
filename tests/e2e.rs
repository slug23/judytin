//! End-to-end: run the judytin binary in --dumb mode against a mock MUD
//! server and check the whole pipeline: banner + prompt display, alias
//! expansion, action triggers, telnet option refusal, disconnect handling.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Spawn a line-echo mock MUD on an ephemeral port. Replies "you said: X"
/// to each line; closes on "quit".
fn spawn_mock() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.write_all(b"Welcome to mockmud\r\n> ").unwrap();
        let mut buf = [0u8; 1024];
        let mut line = Vec::new();
        let mut skip = 0usize;
        'outer: loop {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                if b == 255 {
                    skip = 2;
                    continue;
                }
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if text.is_empty() {
                        continue;
                    }
                    let reply = format!("you said: {}\r\n", text);
                    sock.write_all(reply.as_bytes()).unwrap();
                    if text == "quit" {
                        sock.write_all(b"Goodbye.\r\n").unwrap();
                        break 'outer;
                    }
                    sock.write_all(b"> ").unwrap();
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    (port, handle)
}

fn run_judytin(port: u16, script: &str) -> String {
    run_judytin_with(&["--dumb", "127.0.0.1", &port.to_string()], script, &[])
}

fn run_judytin_with(args: &[&str], script: &str, envs: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_judytin"));
    cmd.args(args);
    // judytin reads ~/.judytinrc at startup, so without this a test measures
    // whoever is running it. A developer who turns on #config {reconnect} in
    // their own rc should not thereby fail the test asserting it defaults off.
    if !envs.iter().any(|(k, _)| *k == "HOME") {
        let empty = std::env::temp_dir().join(format!("judytin-nohome-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let _ = std::fs::remove_file(empty.join(".judytinrc"));
        cmd.env("HOME", &empty);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    // A backstop against a hung client, not a deadline for a slow one. Most
    // of this suite drives a mock server on wall-clock timings, and dozens of
    // those running at once on a busy machine stretch a two-second script
    // well past what it looks like it needs. At fifteen seconds the whole
    // suite failed under `cargo test`'s default parallelism while every test
    // passed on its own — which is a broken test harness, not a broken
    // client.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(90));
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });
    child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn pipe_transport_via_run_command() {
    let script = "\
#run {loop} {sh -c 'echo piped mud ready; while read l; do echo \"you said: $l\"; done'}\n\
say through a pipe\n\
#delay {0.4} {#end}\n";
    let stdout = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(stdout.contains("piped mud ready"), "pipe banner:\n{}", stdout);
    assert!(
        stdout.contains("you said: say through a pipe"),
        "pipe echo:\n{}",
        stdout
    );
}

#[test]
fn tls_transport_with_tofu_pinning() {
    // a throwaway self-signed identity, served twice
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let config = std::sync::Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            tls.write_all(b"Welcome to tlsmud\r\n> ").unwrap();
            let mut buf = [0u8; 1024];
            let mut line = Vec::new();
            'sess: loop {
                let n = match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                for &b in &buf[..n] {
                    if b == b'\n' {
                        let text = String::from_utf8_lossy(&line).trim().to_string();
                        line.clear();
                        if text.is_empty() {
                            continue;
                        }
                        let reply = format!("you said: {}\r\n", text);
                        tls.write_all(reply.as_bytes()).unwrap();
                        if text == "quit" {
                            tls.write_all(b"Goodbye.\r\n").unwrap();
                            tls.conn.send_close_notify();
                            let _ = tls.flush();
                            break 'sess;
                        }
                    } else if b != b'\r' {
                        line.push(b);
                    }
                }
            }
        }
    });

    // isolated HOME so the pin file doesn't touch the real one
    let home = std::env::temp_dir().join(format!("judytin-tofu-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let home_s = home.to_string_lossy().to_string();

    let script = "say secured\nquit\n";
    let args = ["--dumb", "--tls", "127.0.0.1", &port.to_string()];
    let first = run_judytin_with(&args, script, &[("HOME", home_s.as_str())]);
    assert!(first.contains("first connection — pinned"), "no pin notice:\n{}", first);
    assert!(first.contains("you said: say secured"), "tls round trip:\n{}", first);

    let second = run_judytin_with(&args, script, &[("HOME", home_s.as_str())]);
    assert!(
        second.contains("matches the pinned one"),
        "pin not recognized:\n{}",
        second
    );
    assert!(second.contains("Goodbye."), "second session:\n{}", second);

    server.join().unwrap();
    let pins = std::fs::read_to_string(home.join(".judytin_known_hosts")).unwrap();
    assert_eq!(pins.lines().count(), 1, "exactly one pin: {}", pins);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_tls_mud_that_hangs_up_bluntly_still_says_goodbye_plainly() {
    // judymud, and most muds, close the socket after `quit` without sending a
    // TLS close_notify. rustls reports that as an error whose text carries a
    // link to its own manual — true, and none of a player's business. Telnet
    // and pipe both say "connection closed" here; TLS must not be the odd one.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let config = std::sync::Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        tls.write_all(b"Welcome to bluntmud\r\n> ").unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if String::from_utf8_lossy(&buf[..n]).contains("quit") {
                tls.write_all(b"Goodbye.\r\n").unwrap();
                let _ = tls.flush();
                break; // drop the socket — deliberately no close_notify
            }
        }
    });

    // Start from nothing: a pin left by an earlier run under a recycled pid
    // would be a pin for a different throwaway cert, and the mismatch would
    // look like a failure of this test rather than of its housekeeping.
    let home = std::env::temp_dir().join(format!("judytin-blunt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let home_s = home.to_string_lossy().to_string();
    let out = run_judytin_with(
        &["--dumb", "--tls", "127.0.0.1", &port.to_string()],
        "quit\n",
        &[("HOME", home_s.as_str())],
    );
    server.join().unwrap();

    assert!(out.contains("Goodbye."), "never reached the mud:\n{}", out);
    assert!(out.contains("connection closed"), "no plain goodbye:\n{}", out);
    assert!(!out.contains("docs.rs"), "leaked a library manual:\n{}", out);
    assert!(!out.contains("close_notify"), "leaked TLS internals:\n{}", out);
    let _ = std::fs::remove_dir_all(&home);
}

/// A mock that answers `serve` connections in turn and drops the first after a
/// moment — a server restarting under the player, which is what reconnect is
/// for. `count` is how many times it was actually reached.
fn spawn_restarting_mock(
    serve: u32,
    drop_first_after: Duration,
) -> (u16, Arc<Mutex<u32>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(Mutex::new(0u32));
    let c2 = count.clone();
    let handle = std::thread::spawn(move || {
        for n in 0..serve {
            let Ok((mut sock, _)) = listener.accept() else { return };
            *c2.lock().unwrap() += 1;
            let _ = sock.write_all(format!("session {} up\r\n", n + 1).as_bytes());
            if n == 0 {
                std::thread::sleep(drop_first_after);
            } else {
                std::thread::sleep(Duration::from_millis(900));
            }
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    (port, count, handle)
}

/// Drop ANSI SGR sequences, so an assertion can be written in the words a
/// player reads rather than in the escape codes around them.
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A named echo mock, so two of them can be told apart in one transcript.
fn spawn_named_mock(tag: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock.write_all(format!("{} greets you\r\n", tag).as_bytes());
        // An unprompted line later on, which is the interesting case: it may
        // well arrive while this session is not the one being watched.
        if let Ok(mut w) = sock.try_clone() {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1000));
                let _ = w.write_all(format!("{} mutters later\r\n", tag).as_bytes());
            });
        }
        let _ = sock.set_read_timeout(Some(Duration::from_millis(4000)));
        let mut buf = [0u8; 1024];
        let mut line = Vec::new();
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if !text.is_empty() {
                        let _ = sock.write_all(format!("{} heard {}\r\n", tag, text).as_bytes());
                    }
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    (port, handle)
}

#[test]
fn two_sessions_stay_apart_and_typing_follows_the_current_one() {
    let (pa, sa) = spawn_named_mock("alpha");
    let (pb, sb) = spawn_named_mock("beta");
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1}} {{{pa}}}\n\
             #delay {{0.5}} {{#session {{b}} {{127.0.0.1}} {{{pb}}}}}\n\
             #delay {{1.2}} {{hello from b}}\n\
             #delay {{1.8}} {{#session {{a}}}}\n\
             #delay {{2.4}} {{hello from a}}\n\
             #delay {{3.2}} {{#end}}\n"
        ),
        &[],
    );
    sa.join().unwrap();
    sb.join().unwrap();
    // Each line reached the session that was current when it was typed.
    assert!(out.contains("beta heard hello from b"), "b did not get its line:\n{}", out);
    assert!(out.contains("alpha heard hello from a"), "a did not get its line:\n{}", out);
    assert!(!out.contains("alpha heard hello from b"), "line leaked to a:\n{}", out);
    assert!(!out.contains("beta heard hello from a"), "line leaked to b:\n{}", out);
}

#[test]
fn background_output_says_which_session_it_came_from() {
    let (pa, sa) = spawn_named_mock("alpha");
    let (pb, sb) = spawn_named_mock("beta");
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1}} {{{pa}}}\n\
             #delay {{0.5}} {{#session {{b}} {{127.0.0.1}} {{{pb}}}}}\n\
             #delay {{1.2}} {{poke}}\n\
             #delay {{2.2}} {{#end}}\n"
        ),
        &[],
    );
    sa.join().unwrap();
    sb.join().unwrap();
    let out = plain(&out);
    // b is current, so its own text is bare...
    assert!(out.contains("beta heard poke"), "current session went missing:\n{}", out);
    assert!(!out.contains("[b] beta heard poke"), "current session was tagged:\n{}", out);
    // ...while a, which is in the background by the time it mutters, is named.
    assert!(
        out.contains("[a] alpha mutters later"),
        "background output arrived unlabelled:\n{}",
        out
    );
    assert!(
        !out.contains("[b] beta mutters later"),
        "foreground output was labelled:\n{}",
        out
    );
}

#[test]
fn session_lists_what_is_open_and_marks_the_current_one() {
    let (pa, sa) = spawn_named_mock("alpha");
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1}} {{{pa}}}\n\
             #delay {{0.6}} {{#session}}\n\
             #delay {{1.4}} {{#end}}\n"
        ),
        &[],
    );
    sa.join().unwrap();
    let out = plain(&out);
    assert!(
        out.contains("* a — 127.0.0.1:"),
        "listing did not mark the current session:\n{}",
        out
    );
}

#[test]
fn switching_to_a_session_that_is_not_there_says_so() {
    let out = run_judytin_with(&["--dumb", "--offline"], "#session {nope}\n", &[]);
    assert!(
        out.contains("no session called nope"),
        "invented a session:\n{}",
        out
    );
}

#[test]
fn one_session_dropping_does_not_end_a_run_the_others_are_still_in() {
    // A piped run ends when there is nothing left to wait for. That used to be
    // read as "when a connection closes", which was the same thing while
    // judytin held one session and stopped being the same thing the moment it
    // could hold four: the first socket to go took the live ones with it.
    //
    // Found for real — a four-character party against judymud lost three
    // healthy sessions nine seconds in because a fourth dropped.
    // Both sessions are opened up front and `a` is dropped well after, so the
    // order of the two events is fixed. Opening `b` on a #delay that fired at
    // the same moment `a` died made this a coin flip: it failed about a third
    // of the time, on unmodified code, for no reason to do with what it is
    // testing.
    let (pa, _ca, sa) = spawn_restarting_mock(1, Duration::from_millis(900));
    let (pb, sb) = spawn_named_mock("beta");
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1:{pa}}}\n\
             #session {{b}} {{127.0.0.1:{pb}}}\n\
             #delay {{1.6}} {{poke}}\n\
             #delay {{2.4}} {{#end}}\n"
        ),
        &[],
    ));
    sa.join().unwrap();
    sb.join().unwrap();
    assert!(out.contains("session 1 up"), "never reached the first mock:\n{}", out);
    // The proof: b answered something typed a full second after a went away.
    assert!(
        out.contains("beta heard poke"),
        "the run ended with the first socket, taking a live session with it:\n{}",
        out
    );
}

#[test]
fn zapping_one_of_several_leaves_the_others_alone() {
    let (pa, sa) = spawn_named_mock("alpha");
    let (pb, sb) = spawn_named_mock("beta");
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1}} {{{pa}}}\n\
             #delay {{0.5}} {{#session {{b}} {{127.0.0.1}} {{{pb}}}}}\n\
             #delay {{1.2}} {{#zap}}\n\
             #delay {{1.8}} {{still here}}\n\
             #delay {{2.6}} {{#end}}\n"
        ),
        &[],
    );
    sa.join().unwrap();
    sb.join().unwrap();
    assert!(out.contains("closed b — now on a"), "zap did not hand over:\n{}", out);
    // a survived and is now taking the typing.
    assert!(out.contains("alpha heard still here"), "the survivor went deaf:\n{}", out);
}

#[test]
fn player_text_waits_for_the_servers_opening() {
    // The live shape of this: `printf 'guest x\nlook\nquit\n' | judytin` used
    // to flush all three lines before judymud's banner arrived, so a login
    // dialogue got answered blind. Here the server takes its time greeting, and
    // the first thing it must read is still the first thing that was typed —
    // not because the timing worked out, but because judytin waited.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let got: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let g2 = got.clone();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        // A slow, split greeting: the worst case for anything that releases on
        // the first packet it happens to see.
        std::thread::sleep(Duration::from_millis(150));
        let _ = sock.write_all(b"Welcome, slowly\r\n");
        std::thread::sleep(Duration::from_millis(120));
        let _ = sock.write_all(&[255, 251, 86]); // IAC WILL MCCP2, late
        let _ = sock.write_all(b"By what name?\r\n> ");
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
        let mut buf = [0u8; 1024];
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 {
                break;
            }
            g2.lock().unwrap().extend_from_slice(&buf[..n]);
            if g2.lock().unwrap().windows(4).any(|w| w == b"quit") {
                break;
            }
        }
    });
    run_judytin_with(
        &["--dumb", "127.0.0.1", &port.to_string()],
        "myname\nquit\n",
        &[],
    );
    server.join().unwrap();
    let recv = got.lock().unwrap().clone();
    let dont = recv.windows(3).position(|w| w == [255u8, 254, 86]);
    let name = recv
        .windows(6)
        .position(|w| w == b"myname")
        .expect("the typed line never arrived");
    let dont = dont.expect("the client never refused the option");
    assert!(
        dont < name,
        "player text overtook the option refusal: {:?}",
        String::from_utf8_lossy(&recv)
    );
}

#[test]
fn a_silent_server_does_not_swallow_what_was_typed() {
    // The hold is a courtesy, not a gate. A server that says nothing at all
    // must not leave the player's input stuck behind it forever.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let got: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let g2 = got.clone();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        // Not one byte of greeting.
        let _ = sock.set_read_timeout(Some(Duration::from_millis(4000)));
        // One read is the whole question: did anything arrive at all?
        let mut buf = [0u8; 1024];
        if let Ok(n) = sock.read(&mut buf)
            && n > 0
        {
            g2.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    run_judytin_with(
        &["--dumb", "127.0.0.1", &port.to_string()],
        "hello anybody\n#delay {4} {#end}\n",
        &[],
    );
    server.join().unwrap();
    let recv = String::from_utf8_lossy(&got.lock().unwrap().clone()).into_owned();
    assert!(
        recv.contains("hello anybody"),
        "the backstop never fired; input was swallowed: {:?}",
        recv
    );
}

#[test]
fn input_ending_while_connected_says_so_instead_of_going_quiet() {
    let (port, _count, server) = spawn_restarting_mock(1, Duration::from_millis(2500));
    let out = run_judytin_with(&["--dumb", "127.0.0.1", &port.to_string()], "look\n", &[]);
    server.join().unwrap();
    assert!(
        out.contains("input ended, still connected"),
        "a script that forgot #end just hangs with nothing said:\n{}",
        out
    );
}

#[test]
fn a_dropped_session_is_not_chased_unless_asked() {
    let (port, count, server) = spawn_restarting_mock(1, Duration::from_millis(300));
    let out = run_judytin_with(&["--dumb", "127.0.0.1", &port.to_string()], "#config\n", &[]);
    server.join().unwrap();
    assert!(out.contains("reconnect off"), "default is not off:\n{}", out);
    assert!(
        !out.contains("reconnecting in"),
        "chased a drop nobody asked it to chase:\n{}",
        out
    );
    assert_eq!(*count.lock().unwrap(), 1, "connected more than once");
}

#[test]
fn an_armed_session_comes_back_after_the_server_drops_it() {
    let (port, count, server) = spawn_restarting_mock(2, Duration::from_millis(400));
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#config {{reconnect}} {{on}}\n\
             #session {{mud}} {{127.0.0.1}} {{{port}}}\n\
             #delay {{3.0}} {{#end}}\n"
        ),
        &[],
    );
    server.join().unwrap();
    assert!(out.contains("session 1 up"), "never reached the mock:\n{}", out);
    assert!(out.contains("reconnecting in 1s"), "no retry announced:\n{}", out);
    assert!(out.contains("session 2 up"), "did not come back:\n{}", out);
    assert_eq!(*count.lock().unwrap(), 2, "should have connected twice");
}

#[test]
fn zap_means_the_player_left_and_is_not_chased() {
    let (port, count, server) = spawn_restarting_mock(1, Duration::from_millis(2000));
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#config {{reconnect}} {{on}}\n\
             #session {{mud}} {{127.0.0.1}} {{{port}}}\n\
             #delay {{0.6}} {{#zap}}\n\
             #delay {{2.5}} {{#end}}\n"
        ),
        &[],
    );
    server.join().unwrap();
    // Armed, but #zap is the one thing that says "I meant to go".
    assert!(out.contains("connection closed (zap)"), "never zapped:\n{}", out);
    assert!(
        !out.contains("reconnecting in"),
        "chased the player out the door:\n{}",
        out
    );
    assert_eq!(*count.lock().unwrap(), 1, "reconnected after a zap");
}

#[test]
fn reconnect_returns_to_the_last_session_without_retyping_it() {
    let (port, count, server) = spawn_restarting_mock(2, Duration::from_millis(2000));
    // Config still off: asking once is not the same as arming it.
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{mud}} {{127.0.0.1}} {{{port}}}\n\
             #delay {{0.6}} {{#zap}}\n\
             #delay {{1.2}} {{#reconnect}}\n\
             #delay {{2.6}} {{#end}}\n"
        ),
        &[],
    );
    server.join().unwrap();
    assert!(out.contains("session 1 up"), "never reached the mock:\n{}", out);
    assert!(
        out.contains("reconnecting to 127.0.0.1:"),
        "#reconnect did not say where it was going:\n{}",
        out
    );
    assert!(out.contains("session 2 up"), "did not come back:\n{}", out);
    assert_eq!(*count.lock().unwrap(), 2, "should have connected twice");
}

#[test]
fn timestamps_render_in_the_zone_the_system_says() {
    // Two zones with awkward offsets, one of them a 45-minute one, checked
    // against each other rather than against a hardcoded clock: the difference
    // between Kathmandu and UTC is fixed even though "now" is not.
    let read = |tz: &str| -> String {
        let out = run_judytin_with(
            &["--dumb", "--offline"],
            "#echo {%t} {%H:%M %z %Z}\n",
            &[("TZ", tz)],
        );
        // The one line shaped like a clock. Matching on "+" would also catch
        // the banner, which says TinTin++.
        plain(&out)
            .lines()
            .map(|l| l.trim())
            .find(|l| {
                let b = l.as_bytes();
                b.len() > 5 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b':'
            })
            .map(|l| l.to_string())
            .unwrap_or_default()
    };
    let utc = read("UTC");
    assert!(utc.contains("+0000"), "UTC did not render as +0000: {utc}");
    assert!(utc.contains("UTC"), "UTC lost its name: {utc}");

    let kat = read("Asia/Kathmandu");
    assert!(
        kat.contains("+0545"),
        "a 45-minute zone was not read from the system database: {kat}"
    );

    // And the clock actually moved with the offset, not just the label.
    let hh_utc: u32 = utc[..2].parse().expect("hour");
    let hh_kat: u32 = kat[..2].parse().expect("hour");
    assert_ne!(hh_utc, hh_kat, "the offset changed the label but not the time");
}

#[test]
fn an_unreadable_zone_falls_back_to_utc_rather_than_lying() {
    // A TZ naming nothing must not produce a confidently wrong local time.
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        "#echo {%t} {%z %Z}\n",
        &[("TZ", "Nowhere/Nothing")],
    ));
    assert!(
        out.contains("+0000") && out.contains("UTC"),
        "an unknown zone did not fall back honestly:\n{}",
        out
    );
}

#[test]
fn reconnect_without_a_session_says_so_rather_than_guessing() {
    let out = run_judytin_with(&["--dumb", "--offline"], "#reconnect\n", &[]);
    assert!(
        out.contains("no session to return to"),
        "invented a destination:\n{}",
        out
    );
}

#[test]
fn scripting_engine_end_to_end() {
    let (port, server) = spawn_mock();
    let script = "\
#config speedwalk on\n\
#math {x} {2 + 3}\n\
#if {$x == 5} {say math works} {say math broken}\n\
#3 {say thrice}\n\
nesw\n\
#function {dbl} {#math {result} {%1 * 2}}\n\
say doubled @dbl{21}\n\
#loop {1} {3} {i} {say loop $i}\n\
#line oneshot {#action {marker} {say once}}\n\
marker one\n\
marker two\n\
#delay {0.1} {say delayed}\n\
#delay {0.3} {quit}\n";
    let stdout = run_judytin(port, script);
    server.join().unwrap();

    assert!(stdout.contains("you said: say math works"), "if/math:\n{}", stdout);
    assert!(
        !stdout.contains("you said: say math broken"),
        "if took else branch:\n{}",
        stdout
    );
    assert_eq!(
        stdout.matches("you said: say thrice").count(),
        3,
        "#3 repeat:\n{}",
        stdout
    );
    for dir in ["north", "east", "south", "west"] {
        assert!(
            stdout.contains(&format!("you said: {}", dir)),
            "speedwalk {}:\n{}",
            dir,
            stdout
        );
    }
    assert!(stdout.contains("you said: say doubled 42"), "function call:\n{}", stdout);
    for i in 1..=3 {
        assert!(
            stdout.contains(&format!("you said: say loop {}", i)),
            "loop {}:\n{}",
            i,
            stdout
        );
    }
    // the oneshot action fired exactly once despite two triggering lines
    assert_eq!(
        stdout.matches("you said: say once").count(),
        1,
        "oneshot action:\n{}",
        stdout
    );
    assert!(stdout.contains("you said: say delayed"), "delay:\n{}", stdout);
    assert!(stdout.contains("Goodbye."), "delayed quit:\n{}", stdout);
}

#[test]
fn dumb_mode_against_mock_mud() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let received_srv = received.clone();

    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        // banner with an ANSI-colored line, a telnet offer, and a bare prompt
        sock.write_all(b"\x1b[1;33mWelcome to mockmud\x1b[0m\r\n").unwrap();
        sock.write_all(&[255, 251, 86]).unwrap(); // IAC WILL MCCP2
        sock.write_all(b"> ").unwrap();

        let mut buf = [0u8; 1024];
        let mut line = Vec::new();
        let mut skip = 0usize; // swallow IAC cmd opt triples from the client
        'outer: loop {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            received_srv.lock().unwrap().extend_from_slice(&buf[..n]);
            for &b in &buf[..n] {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                if b == 255 {
                    skip = 2;
                    continue;
                }
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if text.is_empty() {
                        continue;
                    }
                    let reply = format!("you said: {}\r\n", text);
                    sock.write_all(reply.as_bytes()).unwrap();
                    if text == "trigger me" {
                        sock.write_all(b"Bob has arrived.\r\n").unwrap();
                    }
                    if text == "hidden" {
                        sock.write_all(b"this is much too secret to show\r\n").unwrap();
                    }
                    if text == "quit" {
                        sock.write_all(b"Goodbye.\r\n").unwrap();
                        // No drain needed: judytin holds player text until the
                        // server's opening is over, so the refusal is already
                        // here. This closing the socket immediately is the point
                        // — it is what the old ordering could not survive.
                        break 'outer;
                    }
                    sock.write_all(b"> ").unwrap();
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_judytin"))
        .args(["--dumb", "127.0.0.1", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // watchdog: kill the child if the test wedges
    let pid = child.id();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(90));
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });

    let script = "\
#alias {gr} {say hi %1}\n\
#action {%1 has arrived} {#showme SEEN ARRIVAL OF %1}\n\
#gag {much too secret}\n\
gr bob\n\
hidden\n\
trigger me\n\
quit\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();

    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    // banner and prompt made it through (ANSI preserved)
    assert!(stdout.contains("Welcome to mockmud"), "missing banner:\n{}", stdout);
    assert!(stdout.contains("\x1b[1;33m"), "ANSI stripped:\n{}", stdout);
    // alias expanded before sending
    assert!(stdout.contains("you said: say hi bob"), "alias not expanded:\n{}", stdout);
    // action fired with capture
    assert!(stdout.contains("SEEN ARRIVAL OF Bob"), "action didn't fire:\n{}", stdout);
    // gag suppressed the server line (the longer phrase appears only in
    // the server's reply, not in judytin's own #gag confirmation)
    assert!(
        !stdout.contains("much too secret to show"),
        "gag failed:\n{}",
        stdout
    );
    // clean shutdown on server close
    assert!(stdout.contains("Goodbye."), "missing goodbye:\n{}", stdout);

    server.join().unwrap();

    // the client refused the MCCP2 offer with IAC DONT 86 and sent no
    // subnegotiation of its own
    let recv = received.lock().unwrap();
    let dont = [255u8, 254, 86];
    assert!(
        recv.windows(3).any(|w| w == dont),
        "client did not refuse MCCP2: {:?}",
        &recv[..]
    );
    assert!(
        !recv.windows(2).any(|w| w == [255, 250]),
        "client sent a subnegotiation"
    );
}

// ---- more than one character, one client -------------------------------

/// A hall several players share, with a party in it.
///
/// The rule that matters: the grue only dies once *every* member of the party
/// has struck it. One connection doing everything cannot satisfy that, so a
/// transcript in which the grue dies is evidence that three separate sessions
/// really acted — not that one session's output was copied three times.
#[derive(Default)]
struct Hall {
    seats: Vec<(String, std::net::TcpStream)>,
    party: Vec<String>,
    struck: Vec<String>,
}

impl Hall {
    fn tell_all(&mut self, text: &str) {
        let msg = format!("{}\r\n", text);
        for (_, w) in self.seats.iter_mut() {
            let _ = w.write_all(msg.as_bytes());
        }
    }
}

fn spawn_party_mud(players: usize) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hall: Arc<Mutex<Hall>> = Arc::new(Mutex::new(Hall::default()));
    let handle = std::thread::spawn(move || {
        let mut threads = Vec::new();
        for _ in 0..players {
            let Ok((sock, _)) = listener.accept() else { break };
            let hall = hall.clone();
            threads.push(std::thread::spawn(move || serve_player(sock, hall)));
        }
        for t in threads {
            let _ = t.join();
        }
    });
    (port, handle)
}

fn serve_player(mut sock: std::net::TcpStream, hall: Arc<Mutex<Hall>>) {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(9000)));
    let _ = sock.write_all(b"The Hall of Mock.\r\nWhat is your name?\r\n");
    let mut me = String::new();
    let mut buf = [0u8; 1024];
    let mut line = Vec::new();
    let mut skip = 0usize;
    loop {
        let n = match sock.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &b in &buf[..n] {
            // telnet negotiation, ignored the way the other mocks ignore it
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if b == 255 {
                skip = 2;
                continue;
            }
            if b != b'\n' {
                if b != b'\r' {
                    line.push(b);
                }
                continue;
            }
            let text = String::from_utf8_lossy(&line).trim().to_string();
            line.clear();
            if text.is_empty() {
                continue;
            }
            if me.is_empty() {
                me = text;
                let _ = sock.write_all(format!("You are {}.\r\n", me).as_bytes());
                let seat = sock.try_clone().unwrap();
                let mut h = hall.lock().unwrap();
                h.tell_all(&format!("{} arrives.", me));
                h.seats.push((me.clone(), seat));
                continue;
            }
            if !obey(&me, &text, &hall) {
                return;
            }
        }
    }
}

/// One command from one player. Returns false when they have left.
fn obey(me: &str, text: &str, hall: &Arc<Mutex<Hall>>) -> bool {
    let (verb, arg) = match text.split_once(' ') {
        Some((v, a)) => (v, a.trim()),
        None => (text, ""),
    };
    let mut h = hall.lock().unwrap();
    match verb {
        "group" => {
            if !h.party.iter().any(|p| p == me) {
                h.party.push(me.to_string());
            }
            let roll = h.party.join(", ");
            h.tell_all(&format!("{} joins the party. Party: {}", me, roll));
        }
        "pull" => h.tell_all("A grue lumbers out of the dark."),
        "strike" => {
            if !h.party.iter().any(|p| p == me) {
                h.tell_all(&format!("{} swings alone and misses.", me));
            } else {
                if !h.struck.iter().any(|p| p == me) {
                    h.struck.push(me.to_string());
                }
                h.tell_all(&format!("{} strikes the grue.", me));
                if h.party.len() > 1 && h.party.iter().all(|p| h.struck.contains(p)) {
                    h.tell_all("The grue dies. The party wins.");
                }
            }
        }
        "say" => h.tell_all(&format!("{} says '{}'", me, arg)),
        "quit" => {
            h.tell_all(&format!("{} leaves the hall.", me));
            return false;
        }
        other => h.tell_all(&format!("{} does not know how to {}.", me, other)),
    }
    true
}

#[test]
fn three_characters_on_three_sessions_group_up_and_play_as_one_party() {
    // The whole point of holding several sessions, done end to end by one
    // judytin: three characters log themselves in under three names, form a
    // party, and kill something that cannot be killed alone.
    //
    // Every new piece of the syntax is load-bearing here. `$session` is how
    // one login trigger serves three characters instead of three near-copies
    // of the same trigger. `#all` is how a party acts together. `#grib pull`
    // is how one character does something the others do not — without the
    // switch-there-and-switch-back dance, which is also what makes the plain
    // `say` two lines later still reach tuk.
    // Each step waits for the server to confirm the one before it, rather than
    // for a clock. Wall-clock chaining was measuring the machine: seven delays
    // that each had to land after a round trip, and on a busy one they stopped
    // landing. Nothing below races, and the only remaining delay is the
    // backstop that stops the test hanging if a step never arrives.
    let (port, mud) = spawn_party_mud(3);
    let script = format!(
        // `say still here` and `#session` go through a short #delay rather than
        // straight into a trigger body. A trigger runs with the session that
        // saw the line as the current one, which is right for `#all` and wrong
        // for these two: they are meant to come from the foreground, and that
        // is exactly what they are here to prove. A timer fires at the top
        // level, so they do.
        //
        // Three logins, in whatever order the sockets happen to be ready.
        // Counting them is what makes "everyone is in" a fact rather than a
        // guess — keying on the last name opened would deadlock whenever that
        // session logged in first.
        "#variable {{in}} {{0}}\n\
         #action {{What is your name}} {{$session}}\n\
         #action {{You are %1.}} {{#math {{in}} {{$in + 1}};#if {{$in == 3}} {{#all {{group}}}}}}\n\
         #line oneshot {{#action {{Party: %1, %2, %3}} {{#grib pull}}}}\n\
         #line oneshot {{#action {{A grue lumbers}} {{#delay {{0.2}} {{say still here}}}}}}\n\
         #line oneshot {{#action {{says 'still here'}} {{#all {{strike}}}}}}\n\
         #line oneshot {{#action {{The grue dies}} \
           {{#delay {{0.2}} {{#session}};#delay {{0.5}} {{#all {{quit}}}}}}}}\n\
         #session {{grib}} {{127.0.0.1:{port}}}\n\
         #session {{sam}} {{127.0.0.1:{port}}}\n\
         #session {{tuk}} {{127.0.0.1:{port}}}\n\
         #delay {{15}} {{#end}}\n"
    );
    let out = plain(&run_judytin_with(&["--dumb", "--offline"], &script, &[]));
    let _ = mud.join();

    // One trigger, three characters: each session answered with its own name.
    for who in ["grib", "sam", "tuk"] {
        assert!(
            out.contains(&format!("You are {}.", who)),
            "{} never logged in — $session did not follow the session:\n{}",
            who,
            out
        );
    }
    // They are one party, and some roll call names all three. Not a fixed
    // order: `#all` sends in session order, but three sockets reaching one
    // server land in whatever order the server's threads get to them, and a
    // test that insisted otherwise would be measuring the mock's scheduling.
    let full_roll = out.lines().any(|l| {
        l.contains("Party: ") && ["grib", "sam", "tuk"].iter().all(|w| l.contains(w))
    });
    assert!(full_roll, "#all did not reach every session:\n{}", out);
    // Only one of them pulled, and it was the one addressed by name.
    assert!(out.contains("A grue lumbers out of the dark."), "nobody pulled:\n{}", out);
    // The kill needs every member to have struck, so this line is the proof.
    assert!(
        out.contains("The grue dies. The party wins."),
        "the party did not all strike — #all missed a session:\n{}",
        out
    );
    // #grib left the focus where it found it, so plain typing still went to
    // tuk, the session opened last.
    assert!(
        out.contains("tuk says 'still here'"),
        "addressing grib stole the focus from tuk:\n{}",
        out
    );
    // ...and the other two heard it from the background, named.
    assert!(
        out.contains("[grib] tuk says 'still here'"),
        "grib did not hear tuk in the background:\n{}",
        out
    );
    // The listing agrees about who is who and where typing goes.
    assert!(out.contains("* tuk"), "the listing lost the current session:\n{}", out);
    assert!(out.contains("  grib"), "the listing lost grib:\n{}", out);
}

#[test]
fn zapping_a_session_by_name_leaves_the_one_you_are_watching() {
    // Closing a background session should not disturb the foreground one.
    // Before #zap took a name this needed switching there and back, which is
    // three commands to do one thing and leaves the focus somewhere else if
    // anything in between goes wrong.
    let (pa, sa) = spawn_named_mock("alpha");
    let (pb, sb) = spawn_named_mock("beta");
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1:{pa}}}\n\
             #delay {{0.5}} {{#session {{b}} {{127.0.0.1:{pb}}}}}\n\
             #delay {{1.2}} {{#zap {{a}}}}\n\
             #delay {{1.6}} {{poke}}\n\
             #delay {{2.4}} {{#end}}\n"
        ),
        &[],
    ));
    let _ = sa.join();
    let _ = sb.join();

    assert!(out.contains("closed a — now on b"), "#zap {{a}} did not close a:\n{}", out);
    // Typing still goes to b, which is where it was going before.
    assert!(out.contains("beta heard poke"), "zapping a took b's focus with it:\n{}", out);
    assert!(!out.contains("alpha heard poke"), "a was still connected:\n{}", out);
}

#[test]
fn a_session_named_after_a_command_says_so_rather_than_going_unreachable() {
    // Commands win over session names, so `#send` stays #send. A player who
    // names a session `send` would otherwise find `#send hi` doing something
    // else entirely, and only find out later.
    let (port, mock) = spawn_named_mock("gamma");
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{send}} {{127.0.0.1:{port}}}\n\
             #delay {{0.8}} {{#end}}\n"
        ),
        &[],
    ));
    let _ = mock.join();
    assert!(
        out.contains("#send is already a command"),
        "opened a shadowed name without a word about it:\n{}",
        out
    );
}

#[test]
fn a_destination_judytin_cannot_read_is_refused_before_anything_opens() {
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        "#session {a} {gopher://mudhost}\n\
         #session {b} {mudhost:99999}\n\
         #session\n\
         #end\n",
        &[],
    ));
    assert!(out.contains("not a transport judytin has"), "took a made-up scheme:\n{}", out);
    assert!(out.contains("is not a port number"), "took a port that cannot exist:\n{}", out);
    // Neither one left a session behind: the listing still has only the
    // unnamed session judytin started with.
    assert!(!out.contains(" a — "), "a bad destination still opened a session:\n{}", out);
    assert!(!out.contains(" b — "), "a bad port still opened a session:\n{}", out);
}

#[test]
fn the_session_nobody_named_can_still_be_addressed() {
    // Connecting from the command line leaves a session with no name, which
    // the listing writes as `-`. Opening a second one beside it must not
    // strand the first: `-` is what a player reads there, so `-` is what
    // addresses it.
    let (pa, sa) = spawn_named_mock("alpha");
    let (pb, sb) = spawn_named_mock("beta");
    let out = plain(&run_judytin_with(
        &["--dumb", "127.0.0.1", &pa.to_string()],
        &format!(
            "#session {{b}} {{127.0.0.1:{pb}}}\n\
             #delay {{0.8}} {{#- poke}}\n\
             #delay {{1.4}} {{#end}}\n"
        ),
        &[],
    ));
    let _ = sa.join();
    let _ = sb.join();
    assert!(out.contains("[-] alpha heard poke"), "`#-` did not reach it:\n{}", out);
    assert!(!out.contains("beta heard poke"), "`#-` went to the wrong session:\n{}", out);
}

/// A mock that speaks judymud's shape: a status prompt carrying the numbers
/// a bot needs, left unterminated the way a real server leaves it.
///
/// `quiet_ms` holds the greeting back so the piped script is registered
/// first. Without it the test measures who won a race, not what the code does.
fn spawn_status_prompt_mud(quiet_ms: u64) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(quiet_ms));
        sock.write_all(b"Welcome to mockmud\r\n30/56hp 12/30m 0g> ").unwrap();
        let mut buf = [0u8; 1024];
        let mut line = Vec::new();
        let mut skip = 0usize;
        loop {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                if b == 255 {
                    skip = 2;
                    continue;
                }
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if text.is_empty() {
                        continue;
                    }
                    // The leading \r\n completes the parked prompt into a
                    // finished line, which is the case where the two trigger
                    // kinds could double-claim the same bytes.
                    let _ = sock.write_all(format!("\r\nyou said: {}\r\n", text).as_bytes());
                    let _ = sock.write_all(b"7/56hp 1/30m 9g> ");
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    (port, handle)
}

/// How many times a trigger actually fired, ignoring judytin's own echo of
/// the script that defined it. Counting raw occurrences instead is how three
/// earlier assertions ended up measuring the test rather than the client.
fn fires(out: &str, tag: &str) -> usize {
    out.lines()
        .filter(|l| !l.contains(">> ") && !l.contains("#ok."))
        .filter(|l| l.contains(tag))
        .count()
}

#[test]
fn prompt_triggers_match_the_prompt_and_line_actions_do_not() {
    let (port, _h) = spawn_status_prompt_mud(700);
    // The same pattern registered both ways, against a prompt that is never
    // completed into a line. Only #prompt can see it.
    let script = "\
#prompt {%1/%2hp %3/%4m} {#showme VITALS %1 %2 %3 %4}\n\
#action {%1/%2hp %3/%4m} {#showme ACTIONFIRED}\n\
#delay {1.6} {#end}\n";
    let out = run_judytin(port, script);
    assert!(out.contains("VITALS 30 56 12 30"), "prompt captures:\n{}", out);
    assert_eq!(fires(&out, "ACTIONFIRED"), 0, "an action claimed a prompt:\n{}", out);
}

#[test]
fn a_prompt_completed_into_a_line_fires_each_kind_once() {
    let (port, _h) = spawn_status_prompt_mud(700);
    // "poke" makes the server continue the parked prompt, so those bytes
    // exist first as a prompt and then at the front of a completed line.
    // Each kind gets its own half: #prompt matches the prompt, #action
    // matches the message that followed it, and neither sees the other's.
    let script = "\
#prompt {%1/%2hp} {#showme PROMPTSAW %1}\n\
#action {%1/%2hp %3/%4m %5g} {#showme LINEHP %1}\n\
#action {you said: %1} {#showme LINESAW %1}\n\
#delay {1.1} {poke}\n\
#delay {2.2} {#end}\n";
    let out = run_judytin(port, script);
    // Two prompts are sent: the greeting's, and the one after the reply.
    assert_eq!(fires(&out, "PROMPTSAW"), 2, "one fire per prompt:\n{}", out);
    assert!(out.contains("PROMPTSAW 30"), "greeting prompt:\n{}", out);
    assert!(out.contains("PROMPTSAW 7"), "prompt after the reply:\n{}", out);
    assert_eq!(fires(&out, "LINESAW poke"), 1, "one fire per line:\n{}", out);
    // This mock terminates its prompt with nothing behind it, so the whole
    // buffer really is the prompt and an action still sees it — judytin
    // cannot tell that from a message whose newline was simply late, and
    // guessing wrong there loses messages, which is far worse. The case that
    // matters, a prompt with a message glued behind it, is covered exactly by
    // a_prompt_already_shown_is_not_glued_onto_the_next_line.
    assert!(fires(&out, "LINEHP") <= 2, "the prompt fired repeatedly:\n{}", out);
}

#[test]
fn a_prompt_trigger_does_not_fire_on_nothing() {
    // Against the live mud a {%1} prompt trigger fired repeatedly with what
    // looked like empty text. A server that sends only complete lines has no
    // prompt at all, so any fire here is judytin inventing one.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        // Every write is a whole, terminated line. Nothing is ever parked.
        for _ in 0..4 {
            let _ = sock.write_all(b"The temple is quiet.\r\n");
            std::thread::sleep(Duration::from_millis(120));
        }
        std::thread::sleep(Duration::from_millis(900));
    });
    let script = "#prompt {%1} {#showme FIRED<%1>}\n#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert_eq!(
        fires(&out, "FIRED<"),
        0,
        "prompt triggers fired with no prompt to match:\n{}",
        out
    );
}

#[test]
fn a_parked_colour_sequence_is_not_a_prompt() {
    // judymud colours its output, and a colour sequence can be left parked
    // with no visible text behind it. Matching that as a prompt hands a bot
    // an empty capture and fires its logic for no reason.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        // A finished line, then a bare colour change with nothing after it.
        let _ = sock.write_all(b"The temple is quiet.\r\n\x1b[31m");
        std::thread::sleep(Duration::from_millis(1200));
    });
    let script = "#prompt {%1} {#showme FIRED<%1>}\n#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert_eq!(
        fires(&out, "FIRED<"),
        0,
        "a colour sequence with no text was treated as a prompt:\n{}",
        out
    );
}

#[test]
fn a_keyed_variable_write_expands_its_name() {
    // $session exists so that one trigger can serve several characters. That
    // only works if the *write* side expands too: storing into hp[$session]
    // must reach hp[<this session>], not a single variable literally named
    // "hp[$session]" that all four characters then share.
    let script = "\
#session alpha 127.0.0.1:1\n\
#variable {role[$session]} {mage}\n\
#showme BYNAME=[$role[alpha]] BYSESSION=[$role[$session]]\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("BYNAME=[mage]"), "write did not expand its key:\n{}", out);
    assert!(out.contains("BYSESSION=[mage]"), "read did not agree with write:\n{}", out);
}

#[test]
fn two_sessions_keep_separate_keyed_state() {
    // The bug this guards: one shared variable meant the last character to
    // report anything overwrote the other three.
    let script = "\
#session alpha 127.0.0.1:1\n\
#variable {hp[$session]} {11}\n\
#session beta 127.0.0.1:1\n\
#variable {hp[$session]} {22}\n\
#showme A=[$hp[alpha]] B=[$hp[beta]]\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("A=[11] B=[22]"), "sessions shared one variable:\n{}", out);
}

#[test]
fn a_variable_can_be_set_to_nothing() {
    // `#variable {x}` asks; `#variable {x} {}` sets empty. A script needs the
    // second to say "this character has no healing spell" as a fact.
    let script = "\
#variable {heal} {cast cure}\n\
#variable {heal} {}\n\
#showme EMPTY=[$heal]\n\
#variable {never}\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("EMPTY=[]"), "empty assignment did not take:\n{}", out);
    assert!(out.contains("no variable {never}"), "querying stopped working:\n{}", out);
}

#[test]
fn a_variable_can_name_the_session_to_run_in() {
    // A roster of generated character names cannot be written into a script,
    // so #$member {cmd} is the only way to drive one member of a crew.
    let script = "\
#session alpha 127.0.0.1:1\n\
#session beta 127.0.0.1:1\n\
#list {crew} {create} {alpha}{beta}\n\
#variable {who} {alpha}\n\
#$who {#showme PICKED-$session}\n\
#$crew[-1] {#showme LAST-$session}\n\
#$nosuch {#showme SHOULD-NOT-RUN}\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("PICKED-alpha"), "a variable did not name a session:\n{}", out);
    assert!(out.contains("LAST-beta"), "a list subscript did not name a session:\n{}", out);
    assert_eq!(fires(&out, "SHOULD-NOT-RUN"), 0, "an unknown name still ran:\n{}", out);
    assert!(out.contains("no session named"), "an unknown name said nothing:\n{}", out);
}

/// A door that asks for a name, refuses whatever it is told, and asks again —
/// then drops, and does the whole thing once more on the next connection.
/// `heard` collects every line it was sent, across both connections.
fn spawn_repromting_door() -> (u16, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h2 = heard.clone();
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept() else { return };
            let _ = sock.set_read_timeout(Some(Duration::from_millis(1400)));
            let _ = sock.write_all(b"By what name do you wish to be known?\r\n");
            let mut buf = [0u8; 512];
            let mut line = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline {
                let n = match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                for &b in &buf[..n] {
                    if b == b'\n' {
                        let text = String::from_utf8_lossy(&line).trim().to_string();
                        line.clear();
                        if text.is_empty() {
                            continue;
                        }
                        h2.lock().unwrap().push(text);
                        // Refuse it and ask again. A trigger that answers this
                        // is the judytin-s66 loop.
                        let _ = sock.write_all(
                            b"That name is already someone's.\r\n\
                              By what name do you wish to be known?\r\n",
                        );
                    } else if b != b'\r' {
                        line.push(b);
                    }
                }
            }
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    (port, heard, handle)
}

#[test]
fn a_login_trigger_answers_once_per_connection_and_again_after_a_reconnect() {
    // This is the pattern bots/core.tin logs in with, and both halves matter.
    // SESSION CONNECTED must re-run the login after a drop, or a crew does not
    // survive the server restarting. And the same trigger must NOT answer a
    // re-prompt on the same connection, or it loops across the network where
    // judytin's depth limits cannot see it — judytin-s66 managed roughly
    // 350,000 round trips in forty seconds that way.
    let (port, heard, server) = spawn_repromting_door();
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#config {{reconnect}} {{on}}\n\
             #variable {{login[mud]}} {{guest bob warrior}}\n\
             #action {{By what name do you wish to be known}} \
               {{#if {{\"$sent[$session]\" == \"\"}} \
                  {{#variable {{sent[$session]}} {{yes}};$login[$session]}} \
                  {{#showme {{REPROMPT-REFUSED}}}}}}\n\
             #event {{SESSION CONNECTED}} {{#variable {{sent[$session]}} {{}}}}\n\
             #session {{mud}} {{127.0.0.1:{port}}}\n\
             #delay {{5.0}} {{#end}}\n"
        ),
        &[],
    );
    let _ = server.join();
    let said = heard.lock().unwrap().clone();
    let logins = said.iter().filter(|l| *l == "guest bob warrior").count();
    assert_eq!(
        logins, 2,
        "expected one login per connection, got {} — {:?}\n{}",
        logins, said, out
    );
    assert!(
        fires(&out, "REPROMPT-REFUSED") >= 2,
        "the re-prompt guard never spoke:\n{}",
        out
    );
}

#[test]
fn a_script_can_tell_a_live_session_from_a_dead_one() {
    // Without this, #all shouts at sessions that are down: during a server
    // restart a crew's hunt ticker produced one refusal per command per
    // session, which buried the reconnect messages.
    let (port, _h) = spawn_status_prompt_mud(0);
    let script = format!(
        "#session live 127.0.0.1:{port}\n\
         #session dead 127.0.0.1:1\n\
         #delay {{1.0}} {{#all {{#showme STATE-$session-$connected}}}}\n\
         #delay {{1.6}} {{#end}}\n"
    );
    let out = run_judytin_with(&["--dumb", "--offline"], &script, &[]);
    assert!(out.contains("STATE-live-1"), "a connected session read as down:\n{}", out);
    assert!(out.contains("STATE-dead-0"), "a refused session read as up:\n{}", out);
}

#[test]
fn a_failed_session_does_not_end_a_run_that_still_has_live_ones() {
    // The focus is wherever the script last put it. A #session that could not
    // connect must not take the connected ones down with it at stdin EOF —
    // during a server restart a failed #session is the normal case, and a
    // crew script would lose the whole run to it.
    // Generous margins on purpose: this failed once in a full parallel run
    // and never on its own, which is the signature of a test measuring load
    // rather than behaviour.
    let (port, _h) = spawn_status_prompt_mud(0);
    let script = format!(
        "#session live 127.0.0.1:{port}\n\
         #session dead 127.0.0.1:1\n\
         #delay {{1.5}} {{#showme STILL-ALIVE}}\n\
         #delay {{3.0}} {{#end}}\n"
    );
    let out = run_judytin_with(&["--dumb", "--offline"], &script, &[]);
    assert!(
        out.contains("input ended, still connected"),
        "quit at EOF with a live session:\n{}",
        out
    );
    assert_eq!(fires(&out, "STILL-ALIVE"), 1, "delays never ran:\n{}", out);
}

#[test]
fn a_server_that_accepts_and_hangs_up_is_backed_away_from() {
    // judymud defends itself — "That is enough for now. The door is shut" —
    // and judytin used to keep knocking once a second regardless, because the
    // backoff was credited on connecting rather than on the connection
    // lasting. Forty refusals in one three-minute run, all judytin's fault.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(0u32));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            *h2.lock().unwrap() += 1;
            let _ = sock.write_all(b"That is enough for now. The door is shut.\r\n");
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    let out = run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#config {{reconnect}} {{on}}\n\
             #session {{mud}} {{127.0.0.1:{port}}}\n\
             #delay {{8.0}} {{#end}}\n"
        ),
        &[],
    );
    // The escalation must actually engage. Before the fix every wait was 1s.
    assert!(out.contains("reconnecting in 1s"), "no first retry:\n{}", out);
    assert!(out.contains("reconnecting in 2s"), "backoff never grew:\n{}", out);
    assert!(out.contains("reconnecting in 4s"), "backoff stalled at 2s:\n{}", out);
    // Eight seconds of 1s knocking would be ~8 hits; escalating gives ~4.
    let n = *hits.lock().unwrap();
    assert!(n <= 5, "knocked {} times in 8s — still hammering:\n{}", n, out);
}

#[test]
fn a_prompt_already_shown_is_not_glued_onto_the_next_line() {
    // judymud parks "30/30hp 12/12m 0g> " and sends the next message behind
    // it. judytin shows the prompt (the packet patch has decided it is one)
    // and then matches the completed line as prompt-plus-message, so every
    // capture anchored at the start of a line silently swallows the prompt.
    //
    // Found the hard way: a bot grouping {%1 starts following you} sent
    // "group 30/30hp 12/12m 0g> Magcoyb" and judymud answered "They are not
    // here." for three minutes.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let _ = sock.write_all(b"You are in a room.\r\n30/30hp 12/12m 0g> ");
        // Well past the 30ms packet patch: judytin has shown this as a prompt.
        std::thread::sleep(Duration::from_millis(400));
        let _ = sock.write_all(b"Magcoyb starts following you.\r\n");
        std::thread::sleep(Duration::from_millis(700));
    });
    let script = "#action {%1 starts following you} {#showme GOT[%1]}\n#delay {2.4} {#end}\n";
    let out = run_judytin(port, script);
    assert!(
        out.contains("GOT[Magcoyb]"),
        "the prompt was glued to the front of the capture:\n{}",
        out
    );
}

#[test]
fn a_line_split_across_packets_is_still_matched_whole() {
    // The other half of the prompt-gluing fix. Within the packet-patch window
    // nothing has been shown, so two packets that are really one line must
    // still match as one — otherwise fixing prompts would break every server
    // that writes a long line in pieces.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let _ = sock.write_all(b"Magcoyb star");
        // Well inside the 30ms patch window: this is one line, not a prompt.
        std::thread::sleep(Duration::from_millis(5));
        let _ = sock.write_all(b"ts following you.\r\n");
        std::thread::sleep(Duration::from_millis(700));
    });
    let script = "#action {%1 starts following you} {#showme GOT[%1]}\n#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert!(
        out.contains("GOT[Magcoyb]"),
        "a split line was not rejoined for matching:\n{}",
        out
    );
}

#[test]
fn a_call_to_a_function_that_is_not_there_says_so_once() {
    // Silence here is expensive: `#if {@playing{} == 1}` compares the string
    // "@playing{}" to "1", is false forever, and the branch never runs. A
    // rewrite that dropped one #function definition cost two full runs
    // against a live server with nothing in the transcript to point at.
    //
    // Once per name, because a missing function inside a six-second ticker
    // across four sessions would otherwise print forty times a minute.
    let script = "\
#function {real} {#return {7}}\n\
#showme A=[@real{}] B=[@nope{}]\n\
#showme C=[@nope{}] D=[@nope{}]\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("A=[7]"), "a real function stopped working:\n{}", out);
    assert_eq!(
        fires(&out, "no function {nope}"),
        1,
        "expected exactly one complaint per name:\n{}",
        out
    );
    // Behaviour is otherwise unchanged: the text is still passed through.
    assert!(out.contains("B=[@nope{}]"), "passthrough changed:\n{}", out);
}

/// A mock that speaks enough judymud for bots/core.tin to react to: a door,
/// a login confirmation, the vitals line, and a refusal for a spell that is
/// beyond a level-1 character.
fn spawn_tiny_judymud() -> (u16, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h2 = heard.clone();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
        std::thread::sleep(Duration::from_millis(600));
        let _ = sock.write_all(b"By what name do you wish to be known?\r\n");
        let mut buf = [0u8; 512];
        let mut line = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(3500);
        while std::time::Instant::now() < deadline {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if b == b'\n' {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if text.is_empty() {
                        continue;
                    }
                    h2.lock().unwrap().push(text.clone());
                    if text.starts_with("guest") {
                        let _ = sock.write_all(
                            b"Welcome, bot. Type help for commands.\r\n\
                              [27/27hp 19/19m 85/85v]\r\n",
                        );
                    } else if text.starts_with("cast") {
                        let _ = sock.write_all(
                            b"You are not yet learned enough for cause light (level 2).\r\n",
                        );
                    } else if text.starts_with("kill") {
                        // Standing in a safe room: the crew must walk out of
                        // it rather than swing at it for five minutes, which
                        // is what a stranded cleric did for a whole run.
                        let _ = sock.write_all(
                            b"Something about this place refuses violence.\r\n",
                        );
                    }
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    (port, heard, handle)
}

#[test]
fn the_shipped_bot_files_load_and_their_triggers_fire() {
    // bots/ is a working bot and also a test of judytin. It only tests
    // anything if it still runs: a rewrite once dropped one #function
    // definition, every gate that called it silently became false, and the
    // crew stood in a room full of things to kill sending nothing at all for
    // two five-minute runs. That is the failure this guards.
    let (port, heard, server) = spawn_tiny_judymud();
    let script = format!(
        "#read bots/core.tin\n\
         #variable {{login[mud]}} {{guest bot cleric}}\n\
         #session {{mud}} {{127.0.0.1:{port}}}\n\
         #variable {{role[mud]}} {{cleric}}\n\
         #variable {{atk[mud]}} {{cast 'cause light'}}\n\
         #variable {{atkspell[mud]}} {{cause light}}\n\
         #variable {{wimpy[mud]}} {{25}}\n\
         #variable {{aimat[mud]}} {{0}}\n\
         #delay {{2.0}} {{crewfight}}\n\
         #delay {{3.0}} {{#showme GATE=@playing{{}} HP=$hp[mud] ATK=$atk[mud]}}\n\
         #delay {{3.6}} {{#end}}\n"
    );
    let out = run_judytin_with(&["--dumb", "--offline"], &script, &[]);
    let _ = server.join();
    let said = heard.lock().unwrap().clone();

    // Every @name{} in the files resolves. This is the cheap half and the
    // half that would have saved ten minutes of live play.
    assert!(
        !out.contains("no function"),
        "a bot file calls a function that is not defined:\n{}",
        out
    );
    // The login trigger answered the door.
    assert!(
        said.iter().any(|l| l == "guest bot cleric"),
        "the crew never logged in — heard {:?}\n{}",
        said,
        out
    );
    // The vitals line was parsed into per-session state, and being in the
    // world was noticed, so the gate that guards every game command is open.
    assert!(out.contains("GATE=1"), "@playing{{}} never opened:\n{}", out);
    assert!(out.contains("HP=27"), "the vitals line was not parsed:\n{}", out);
    // And the crew learned it cannot cast what it asked for, falling back to
    // melee rather than repeating a spell it does not have.
    assert!(
        said.iter().any(|l| l.starts_with("cast")),
        "never tried its spell — heard {:?}\n{}",
        said,
        out
    );
    assert!(out.contains("ATK=kill"), "did not fall back to melee:\n{}", out);
    // Refused by a safe room, it walks its route out instead of standing
    // there. A cleric that never did this kept 12 experience for four runs
    // while the rest of the crew reached level 3.
    assert!(
        said.iter().any(|l| l == "recall"),
        "stayed in the safe room after being refused — heard {:?}\n{}",
        said,
        out
    );
}

#[test]
fn a_variable_can_name_a_file_to_read() {
    // One alias has to be able to load the right class file for a character,
    // and the roster is generated, so the names cannot be written into the
    // launcher. #system already substituted its argument; these did not.
    let dir = std::env::temp_dir().join(format!("judytin-readvar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("chosen.tin");
    std::fs::write(&file, "#showme FROM-THE-FILE\n").unwrap();
    let script = format!(
        "#variable {{which}} {{chosen}}\n\
         #read {}/$which.tin\n\
         #end\n",
        dir.display()
    );
    let out = run_judytin_with(&["--dumb", "--offline"], &script, &[]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.contains("FROM-THE-FILE"),
        "a variable could not name a file to read:\n{}",
        out
    );
}

/// A judymud-shaped door that issues a resume key on first login, then dies
/// once — a server restart under a crew that is mid-fight.
fn spawn_restarting_door() -> (u16, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h2 = heard.clone();
    let handle = std::thread::spawn(move || {
        for round in 0..2 {
            let Ok((mut sock, _)) = listener.accept() else { return };
            let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
            std::thread::sleep(Duration::from_millis(500));
            let _ = sock.write_all(b"By what name do you wish to be known?\r\n");
            let mut buf = [0u8; 512];
            let mut line = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_millis(2200);
            while std::time::Instant::now() < deadline {
                let n = match sock.read(&mut buf) {
                    Ok(0) | Err(_) => continue,
                    Ok(n) => n,
                };
                for &b in &buf[..n] {
                    if b == b'\n' {
                        let text = String::from_utf8_lossy(&line).trim().to_string();
                        line.clear();
                        if text.is_empty() {
                            continue;
                        }
                        h2.lock().unwrap().push(text.clone());
                        if text.starts_with("guest") {
                            // The name is free the first time and taken after.
                            if round == 0 {
                                let _ = sock.write_all(
                                    b"Welcome, bot. Type help for commands.\r\n\
                                      Your resume key is NotARealKey1 \xe2\x80\x94 keep it. \
                                      `resume bot NotARealKey1` brings you back, and so \
                                      does your name at the door.\r\n",
                                );
                            } else {
                                let _ = sock.write_all(b"That name is already someone\'s.\r\n");
                            }
                        } else if text.starts_with("resume") {
                            let _ = sock.write_all(b"Welcome back.\r\n");
                        }
                    } else if b != b'\r' {
                        line.push(b);
                    }
                }
            }
            let _ = sock.shutdown(std::net::Shutdown::Both);
        }
    });
    (port, heard, handle)
}

#[test]
fn a_crew_comes_back_with_resume_after_a_restart_not_guest() {
    // `guest` works exactly once. Before the bot learned to swap its own
    // login, the first judymud restart locked the whole crew out: the stored
    // login was re-sent, the name was taken, and four characters that had
    // been mid-fight never got back in.
    //
    // Storing the key in a variable is allowed where writing it to a file is
    // not, and that difference is the point: the key is server text, kept
    // escaped, unescaped once when it is sent back at the door.
    let (port, heard, server) = spawn_restarting_door();
    let script = format!(
        "#read bots/core.tin\n\
         #config {{reconnect}} {{on}}\n\
         #variable {{login[mud]}} {{guest bot cleric}}\n\
         #variable {{wimpy[mud]}} {{25}}\n\
         #variable {{isleader[mud]}} {{yes}}\n\
         #session {{mud}} {{127.0.0.1:{port}}}\n\
         #delay {{6.0}} {{#end}}\n"
    );
    let out = run_judytin_with(&["--dumb", "--offline"], &script, &[]);
    let _ = server.join();
    let said = heard.lock().unwrap().clone();
    assert!(
        said.iter().any(|l| l == "guest bot cleric"),
        "never logged in the first time — heard {:?}\n{}",
        said,
        out
    );
    assert!(
        said.iter().any(|l| l == "resume bot NotARealKey1"),
        "came back with the wrong login after the restart — heard {:?}\n{}",
        said,
        out
    );
    // And exactly once with guest: a second guest is the lock-out.
    assert_eq!(
        said.iter().filter(|l| l.starts_with("guest")).count(),
        1,
        "sent guest again after the name was taken — heard {:?}\n{}",
        said,
        out
    );
}

#[test]
fn a_burst_the_player_asked_for_is_not_throttled() {
    // The trigger-loop ceiling counts only server-caused sends. A script the
    // player runs may be as busy as it likes: 150 lines at once is a mapper
    // walking a path, not a conversation answering itself.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(0u32));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
        std::thread::sleep(Duration::from_millis(500));
        let _ = sock.write_all(b"ready\r\n");
        let mut buf = [0u8; 8192];
        let deadline = std::time::Instant::now() + Duration::from_millis(2500);
        while std::time::Instant::now() < deadline {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => *s2.lock().unwrap() += buf[..n].iter().filter(|&&b| b == b'\n').count() as u32,
                Err(_) => continue,
            }
        }
    });
    let out = run_judytin(port, "#delay {1.0} {#150 {look}}\n#delay {2.2} {#end}\n");
    let n = *seen.lock().unwrap();
    assert_eq!(n, 150, "a player-driven burst was throttled: server saw {}\n{}", n, out);
    assert!(
        !out.contains("lines in a second"),
        "the trigger ceiling fired on the player's own script:\n{}",
        out
    );
}

#[test]
fn a_declared_prompt_is_stripped_even_when_it_shares_a_packet() {
    // judytin-w9e. The packet-patch boundary cannot help when a server writes
    // its prompt and the next message in one write: nothing separates them.
    // A #prompt pattern is the script saying what its prompt looks like, and
    // taking it at its word costs no heuristics.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        // Prompt and message in a single write, exactly as judymud does it.
        let _ = sock.write_all(b"30/30hp 12/12m 0g> Magcoyb starts following you.\r\n");
        std::thread::sleep(Duration::from_millis(800));
    });
    let script = "\
#prompt {%1/%2hp %3/%4m %5g>} {#nop just declaring the shape}\n\
#action {%1 starts following you} {#showme GOT[%1]}\n\
#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert!(
        out.contains("GOT[Magcoyb]"),
        "a declared prompt was still glued to the capture:\n{}",
        out
    );
}

#[test]
fn without_a_declared_prompt_nothing_is_stripped() {
    // The fix must not guess. With no #prompt registered, a line is whatever
    // the server sent, exactly as before.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let _ = sock.write_all(b"30/30hp 12/12m 0g> Magcoyb starts following you.\r\n");
        std::thread::sleep(Duration::from_millis(800));
    });
    let script = "#action {%1 starts following you} {#showme GOT[%1]}\n#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert!(
        out.contains("GOT[30/30hp 12/12m 0g> Magcoyb]"),
        "something was stripped without being asked:\n{}",
        out
    );
}

#[test]
fn a_line_that_is_only_a_prompt_still_reaches_actions() {
    // Stripping a prompt that is the whole line would leave nothing, which
    // silences triggers rather than aiming them.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(700));
        let _ = sock.write_all(b"30/30hp 12/12m 0g>\r\n");
        std::thread::sleep(Duration::from_millis(800));
    });
    let script = "\
#prompt {%1/%2hp %3/%4m %5g>} {#nop shape}\n\
#action {%1/%2hp %3/%4m %5g>} {#showme WHOLE[%1]}\n\
#delay {2.0} {#end}\n";
    let out = run_judytin(port, script);
    assert!(out.contains("WHOLE[30]"), "a prompt-only line was emptied:\n{}", out);
}

#[test]
fn a_piped_login_script_catches_the_door() {
    // judytin-iz5. Startup used to open the socket and only afterwards begin
    // reading stdin, so the greeting had a head start on the trigger written
    // to catch it: the #action registered after the door prompt had already
    // been processed and never fired, leaving the character at the prompt
    // while the rest of the script ran into the void.
    //
    // The mock answers immediately, which is the losing case — a local
    // server has the greeting on the wire before a piped script is read.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h2 = heard.clone();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1200)));
        // No pause at all: greet the instant the socket opens.
        let _ = sock.write_all(b"By what name do you wish to be known?\r\n");
        let mut buf = [0u8; 512];
        let mut line = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);
        while std::time::Instant::now() < deadline {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => continue,
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if b == b'\n' {
                    let t = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if !t.is_empty() {
                        h2.lock().unwrap().push(t);
                    }
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    let out = run_judytin(
        port,
        "#action {By what name do you wish to be known} {guest bob warrior}\n\
         #delay {1.6} {#end}\n",
    );
    let said = heard.lock().unwrap().clone();
    assert!(
        said.iter().any(|l| l == "guest bob warrior"),
        "the login trigger missed the door — heard {:?}\n{}",
        said,
        out
    );
}

#[test]
fn a_piped_command_before_the_connection_still_arrives() {
    // The other half: reading the script first must not make a script whose
    // first line is an ordinary command fail with "not connected". It waits
    // for the socket instead of being refused by it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h2 = heard.clone();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1200)));
        let _ = sock.write_all(b"Welcome.\r\n");
        let mut buf = [0u8; 512];
        let mut line = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(1500);
        while std::time::Instant::now() < deadline {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => continue,
                Ok(n) => n,
            };
            for &b in &buf[..n] {
                if b == b'\n' {
                    let t = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if !t.is_empty() {
                        h2.lock().unwrap().push(t);
                    }
                } else if b != b'\r' {
                    line.push(b);
                }
            }
        }
    });
    let out = run_judytin(port, "look\n#delay {1.6} {#end}\n");
    let said = heard.lock().unwrap().clone();
    assert!(
        said.iter().any(|l| l == "look"),
        "a command sent before the socket was open got lost — heard {:?}\n{}",
        said,
        out
    );
    assert!(
        !out.contains("not connected"),
        "the script was refused instead of queued:\n{}",
        out
    );
}

#[test]
fn a_list_can_be_walked_the_way_tt_plus_plus_writes_it() {
    // judytin-c04. $name[%*] is every item at once, which is how tt++ spells
    // an iteration. Without it the subscript was taken literally, #foreach
    // received the string "$prey[%*]" and looped once over that — a single
    // bogus iteration that looks like it ran, which is the worst outcome.
    let script = "\
#list {prey} {create} {believer}{apprentice}{pilferer}\n\
#showme ALL=[$prey[%*]]\n\
#foreach {$prey[%*]} {t} {#showme HIT=[$t]}\n\
#showme GONE=[$nosuchlist[%*]]\n\
#end\n";
    let out = run_judytin_with(&["--dumb", "--offline"], script, &[]);
    assert!(out.contains("ALL=[believer;apprentice;pilferer]"), "no %* expansion:\n{}", out);
    assert_eq!(fires(&out, "HIT="), 3, "#foreach did not walk the list:\n{}", out);
    assert!(out.contains("HIT=[pilferer]"), "last item missing:\n{}", out);
    // A list that does not exist is empty, not its own name.
    assert!(out.contains("GONE=[]"), "an absent list expanded to itself:\n{}", out);
}
