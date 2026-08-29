//! End-to-end: run the judytin binary in --dumb mode against a mock MUD
//! server and check the whole pipeline: banner + prompt display, alias
//! expansion, action triggers, telnet option refusal, disconnect handling.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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
