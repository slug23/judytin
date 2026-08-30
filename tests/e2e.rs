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
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(15));
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
        std::thread::sleep(std::time::Duration::from_secs(15));
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
