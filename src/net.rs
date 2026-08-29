//! Connection transports: plain TCP, TLS with trust-on-first-use pinning,
//! and subprocess pipes (which is how --ssh works: the system `ssh -T` is
//! the byte pipe, so keys, agent, and known_hosts all behave like normal
//! ssh).
//!
//! Every transport feeds the same Ev::Net / Ev::NetClosed events, so the
//! telnet layer and everything above it cannot tell them apart.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::app::Ev;

pub enum Conn {
    Tcp(TcpStream),
    /// pump thread owns the TLS stream; we hold its outgoing queue
    Tls(Sender<Vec<u8>>),
    /// child process; its stdout/stderr feed Ev::Net
    Pipe { stdin: std::process::ChildStdin, child: Child },
}

impl Conn {
    pub fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => {
                s.write_all(bytes)?;
                s.flush()
            }
            Conn::Tls(tx) => tx
                .send(bytes.to_vec())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "tls pump gone")),
            Conn::Pipe { stdin, .. } => {
                stdin.write_all(bytes)?;
                stdin.flush()
            }
        }
    }

    pub fn shutdown(&mut self) {
        match self {
            Conn::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Conn::Tls(_) => {} // dropping the sender stops the pump
            Conn::Pipe { child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// A short label for messages: "tls", "ssh", or "telnet".
    pub fn kind(&self) -> &'static str {
        match self {
            Conn::Tcp(_) => "telnet",
            Conn::Tls(_) => "tls",
            Conn::Pipe { .. } => "pipe",
        }
    }
}

fn resolve(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
}

// ---- plain TCP ----------------------------------------------------------

pub fn connect_tcp(host: &str, port: u16, id: u64, tx: Sender<Ev>) -> Result<Conn, String> {
    let addr = resolve(host, port).map_err(|e| e.to_string())?;
    let stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);
    let mut reader = stream.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(Ev::NetClosed(id, "connection closed".into()));
                    break;
                }
                Ok(n) => {
                    if tx.send(Ev::Net(id, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Ev::NetClosed(id, e.to_string()));
                    break;
                }
            }
        }
    });
    Ok(Conn::Tcp(stream))
}

// ---- TLS with trust-on-first-use ----------------------------------------

/// What the TOFU check decided, reported back for user messaging.
pub enum Pin {
    /// first sight: fingerprint stored
    New(String),
    /// matched the stored fingerprint
    Known,
}

fn known_hosts_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home).join(".judytin_known_hosts")
}

/// What the pin file says about a host.
enum Pinned {
    /// Never seen; first sight will pin it.
    Absent,
    Fingerprint(String),
    /// An entry exists but is unreadable. Deliberately distinct from
    /// `Absent`: treating a damaged line as "no pin" would silently turn
    /// pinning off for exactly the host someone tampered with, while the
    /// client cheerfully reported a first connection.
    Malformed,
}

fn load_pin(hostport: &str) -> Pinned {
    let Ok(content) = std::fs::read_to_string(known_hosts_path()) else {
        return Pinned::Absent;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some(hostport) {
            continue;
        }
        return match parts.next() {
            Some(fp) if fp.starts_with("sha256:") && fp.len() == 7 + 64 => {
                Pinned::Fingerprint(fp.to_string())
            }
            _ => Pinned::Malformed,
        };
    }
    Pinned::Absent
}

fn store_pin(hostport: &str, fp: &str) -> std::io::Result<()> {
    let path = known_hosts_path();
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    writeln!(f, "{} {}", hostport, fp)
}

#[derive(Debug)]
struct TofuVerifier {
    expected: Option<String>,
    seen: std::sync::Mutex<Option<String>>,
}

fn fingerprint(cert: &[u8]) -> String {
    let hash = Sha256::digest(cert);
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha256:{}", hex)
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.expected {
            Some(e) if *e != fp => Err(rustls::Error::General(format!(
                "server certificate changed! pinned {}, got {}",
                e, fp
            ))),
            _ => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn connect_tls(
    host: &str,
    port: u16,
    id: u64,
    tx: Sender<Ev>,
) -> Result<(Conn, Pin), String> {
    let hostport = format!("{}:{}", host, port);
    let (expected, had_pin) = match load_pin(&hostport) {
        Pinned::Fingerprint(fp) => (Some(fp), true),
        Pinned::Absent => (None, false),
        Pinned::Malformed => {
            return Err(format!(
                "the pin for {} in {} is unreadable. Refusing to connect rather than \
                 silently trusting a new certificate — remove that line to start over.",
                hostport,
                known_hosts_path().display()
            ));
        }
    };
    let verifier = Arc::new(TofuVerifier { expected, seen: std::sync::Mutex::new(None) });

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .dangerous()
    .with_custom_certificate_verifier(verifier.clone())
    .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid server name '{}'", host))?;
    let addr = resolve(host, port).map_err(|e| e.to_string())?;
    let sock =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    let _ = sock.set_nodelay(true);

    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    // finish the handshake while the socket is still blocking
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
    }

    let pin = {
        let seen = verifier.seen.lock().unwrap().clone();
        match (seen, had_pin) {
            (Some(fp), false) => {
                store_pin(&hostport, &fp).map_err(|e| format!("cannot save pin: {}", e))?;
                Pin::New(fp)
            }
            (Some(_), true) => Pin::Known,
            // The verifier never ran, so nothing was checked. Say so rather
            // than reporting a match we did not make.
            (None, _) => {
                return Err("TLS finished without presenting a certificate".to_string());
            }
        }
    };

    // pump thread: short read timeout interleaves reads with queued writes
    tls.sock
        .set_read_timeout(Some(Duration::from_millis(25)))
        .map_err(|e| e.to_string())?;
    let (out_tx, out_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            loop {
                match out_rx.try_recv() {
                    Ok(data) => {
                        if tls.write_all(&data).and_then(|_| tls.flush()).is_err() {
                            let _ = tx.send(Ev::NetClosed(id, "TLS write failed".into()));
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                        return;
                    }
                }
            }
            match tls.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(Ev::NetClosed(id, "connection closed".into()));
                    return;
                }
                Ok(n) => {
                    if tx.send(Ev::Net(id, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                // A mud that drops the socket after `quit` without a TLS
                // close_notify is doing something ordinary, and rustls' own
                // manual says to treat it as a clean close. The player gets
                // the same goodbye as on telnet rather than a library error
                // and a documentation link. Real TLS faults arrive as other
                // error kinds and still say what they were.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    let _ = tx.send(Ev::NetClosed(id, "connection closed".into()));
                    return;
                }
                Err(e) => {
                    let _ = tx.send(Ev::NetClosed(id, e.to_string()));
                    return;
                }
            }
        }
    });
    Ok((Conn::Tls(out_tx), pin))
}

// ---- subprocess pipe (ssh and friends) ----------------------------------

/// Run `command` as the byte pipe. `ssh_dest`, when set, says this pipe is
/// an ssh we built ourselves rather than an arbitrary `#run`, which is what
/// makes it safe to read a meaning into the child's stderr: only then do we
/// know the process on the other end is ssh, and only then do we have a
/// destination to name in the advice.
pub fn connect_pipe(
    command: &str,
    ssh_dest: Option<&str>,
    id: u64,
    tx: Sender<Ev>,
) -> Result<Conn, String> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let mut r = stdout;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) => {
                    let _ = tx2.send(Ev::NetClosed(id, "connection closed".into()));
                    break;
                }
                Ok(n) => {
                    if tx2.send(Ev::Net(id, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx2.send(Ev::NetClosed(id, e.to_string()));
                    break;
                }
            }
        }
    });
    // stderr (ssh banners, errors) is shown as data too, so the user sees
    // what went wrong when a key is refused
    let help = ssh_dest.map(ssh_unknown_host_help);
    std::thread::spawn(move || {
        let mut r = stderr;
        let mut buf = [0u8; 8192];
        let mut watch = SshWatch::new();
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let matched = help.is_some() && watch.feed(&buf[..n]);
            if tx.send(Ev::Net(id, buf[..n].to_vec())).is_err() {
                break;
            }
            // After ssh's own line, so the transcript reads as the failure
            // followed by the explanation rather than the other way round.
            if matched
                && let Some(h) = &help
                && tx.send(Ev::NetDiag(id, h.clone())).is_err()
            {
                break;
            }
        }
    });
    Ok(Conn::Pipe { stdin, child })
}

/// ssh's words when it meets a host whose key it has never seen. With
/// BatchMode on it cannot ask, so this is where a first connection stops.
const SSH_UNKNOWN_HOST: &str = "Host key verification failed";

/// Split `user@host:port` into the part ssh calls a destination and the port.
fn split_dest(dest: &str) -> (&str, Option<&str>) {
    match dest.rsplit_once(':') {
        Some((t, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (t, Some(p)),
        _ => (dest, None),
    }
}

/// Watches ssh's stderr for the one line judytin has something to add to.
///
/// Kept out of the reader thread so the awkward part is testable: the verdict
/// can arrive split across two reads, and the buffer that stitches the halves
/// together must not grow with a talkative child.
struct SshWatch {
    tail: String,
    said: bool,
}

impl SshWatch {
    /// Enough to hold the phrase across any seam, small enough that a child
    /// spraying stderr cannot make judytin hold the spray.
    const MAX: usize = 4096;

    fn new() -> Self {
        Self { tail: String::new(), said: false }
    }

    /// True exactly once: on the chunk that completes the phrase.
    fn feed(&mut self, chunk: &[u8]) -> bool {
        if self.said {
            return false;
        }
        self.tail.push_str(&String::from_utf8_lossy(chunk));
        if self.tail.contains(SSH_UNKNOWN_HOST) {
            self.said = true;
            self.tail = String::new();
            return true;
        }
        if self.tail.len() > Self::MAX {
            // Keep only what a phrase could still be straddling. The scan for
            // a boundary is because stderr is arbitrary bytes: from_utf8_lossy
            // gives valid UTF-8, but not one whose char edges we chose.
            let want = self.tail.len() - SSH_UNKNOWN_HOST.len();
            let cut = (want..=self.tail.len())
                .find(|&i| self.tail.is_char_boundary(i))
                .unwrap_or(self.tail.len());
            self.tail.drain(..cut);
        }
        false
    }
}

/// What to tell a player whose first ssh connection just bounced.
///
/// judytin pins TLS certificates itself the first time it sees them, but ssh
/// keeps its own known_hosts and we run it with BatchMode on — there is no
/// terminal behind the pipe, so a trust prompt would hang where nobody could
/// answer it. The decision therefore stays with ssh, and has to be made once,
/// deliberately, outside judytin. Saying so is the whole point: ssh's one
/// line reads like judytin failing to connect, and it is not.
pub fn ssh_unknown_host_help(dest: &str) -> String {
    let (target, port) = split_dest(dest);
    let host = target.rsplit_once('@').map_or(target, |(_, h)| h);
    let port_arg = port.map(|p| format!("-p {} ", p)).unwrap_or_default();
    format!(
        "that is ssh refusing a host it has no key for, not judytin failing \
         to reach it. judytin runs ssh with BatchMode on, so ssh cannot stop \
         to ask whether you trust this server. Check the key against what the \
         server's owner published, and if it matches, tell ssh once: \
         ssh-keyscan {}{} >> ~/.ssh/known_hosts",
        port_arg,
        shell_quote(host),
    )
}

/// Build the ssh command line for --ssh / #ssh. A trailing `:port` on the
/// destination becomes `-p port`.
pub fn ssh_command(dest: &str) -> String {
    let (target, port) = split_dest(dest);
    let port_arg = port.map(|p| format!("-p {} ", p)).unwrap_or_default();
    // `--` so a destination beginning with '-' is a destination and not an
    // option: without it, `--ssh -oProxyCommand=...` would be handed to ssh
    // as configuration rather than a host to reach.
    format!(
        "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 {}-- {}",
        port_arg,
        shell_quote(target)
    )
}

fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_alphanumeric() || "@.:-_/".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable() {
        let fp = fingerprint(b"hello");
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), 7 + 64);
        assert_eq!(fp, fingerprint(b"hello"));
        assert_ne!(fp, fingerprint(b"world"));
    }

    #[test]
    fn ssh_command_quotes_and_ports() {
        assert_eq!(
            ssh_command("play@mud.example.org"),
            "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 -- play@mud.example.org"
        );
        assert_eq!(
            ssh_command("grib@127.0.0.1:2322"),
            "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 -p 2322 -- grib@127.0.0.1"
        );
        assert!(ssh_command("a b").ends_with("'a b'"));
    }

    #[test]
    fn unknown_host_help_names_the_port_and_the_host() {
        let h = ssh_unknown_host_help("grib@mud.example.org:2322");
        assert!(
            h.contains("ssh-keyscan -p 2322 mud.example.org >> ~/.ssh/known_hosts"),
            "no usable remedy: {h}"
        );
        // The user part is ssh's business, not keyscan's.
        assert!(!h.contains("grib@"), "leaked the username into keyscan: {h}");
        // Default port stays implicit, as ssh-keyscan expects.
        let d = ssh_unknown_host_help("play@mud.example.org");
        assert!(d.contains("ssh-keyscan mud.example.org >>"), "{d}");
        // A hostile destination cannot smuggle shell into copy-pasteable advice.
        let q = ssh_unknown_host_help("me@evil; rm -rf ~");
        assert!(q.contains("'evil; rm -rf ~'"), "advice not quoted: {q}");
    }

    #[test]
    fn watch_fires_once_even_when_split_across_reads() {
        let mut w = SshWatch::new();
        assert!(!w.feed(b"ssh: Host key verifi"));
        assert!(w.feed(b"cation failed.\r\n"), "missed the seam");
        // Only ever once: the advice is not repeated for every later byte.
        assert!(!w.feed(b"Host key verification failed.\r\n"));
    }

    #[test]
    fn watch_does_not_grow_with_a_talkative_child() {
        let mut w = SshWatch::new();
        for _ in 0..64 {
            assert!(!w.feed(&[b'x'; 4096]));
        }
        assert!(w.tail.len() <= SshWatch::MAX + 4096, "buffer ran away: {}", w.tail.len());
        // Still watching, and still able to match after the trimming.
        assert!(w.feed(b"Host key verification failed."));
    }

    #[test]
    fn watch_survives_a_multibyte_boundary_in_the_trim() {
        let mut w = SshWatch::new();
        // A wall of multibyte characters means the trim point almost never
        // lands on a char boundary by luck.
        for _ in 0..64 {
            assert!(!w.feed("é".repeat(2048).as_bytes()));
        }
        assert!(w.feed(b"Host key verification failed."));
    }

    #[test]
    fn ssh_destination_cannot_smuggle_options() {
        // A destination beginning with '-' would otherwise be read by ssh as
        // configuration — `-oProxyCommand=…` being the interesting one.
        let cmd = ssh_command("-oProxyCommand=touch /tmp/x");
        let after = cmd.split(" -- ").nth(1).expect("a -- separator");
        assert!(after.starts_with('\''), "destination not quoted: {cmd}");
        assert!(
            cmd.contains(" -- '-oProxyCommand=touch /tmp/x'"),
            "destination not confined behind --: {cmd}"
        );
    }
}
