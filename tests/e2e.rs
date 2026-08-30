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
fn one_session_dropping_does_not_end_a_run_the_others_are_still_in() {
    // A piped run ends when there is nothing left to wait for. That used to be
    // read as "when a connection closes", which was the same thing while
    // judytin held one session and stopped being the same thing the moment it
    // could hold four: the first socket to go took the live ones with it.
    //
    // Found for real — a four-character party against judymud lost three
    // healthy sessions nine seconds in because a fourth dropped.
    let (pa, _ca, sa) = spawn_restarting_mock(1, Duration::from_millis(400));
    let (pb, sb) = spawn_named_mock("beta");
    let out = plain(&run_judytin_with(
        &["--dumb", "--offline"],
        &format!(
            "#session {{a}} {{127.0.0.1:{pa}}}\n\
             #delay {{0.4}} {{#session {{b}} {{127.0.0.1:{pb}}}}}\n\
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
