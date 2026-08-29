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

fn load_pin(hostport: &str) -> Option<String> {
    let content = std::fs::read_to_string(known_hosts_path()).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(hostport) {
            return parts.next().map(|s| s.to_string());
        }
    }
    None
}

fn store_pin(hostport: &str, fp: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_hosts_path())?;
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
    let expected = load_pin(&hostport);
    let had_pin = expected.is_some();
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
        match seen {
            Some(fp) if !had_pin => {
                store_pin(&hostport, &fp).map_err(|e| format!("cannot save pin: {}", e))?;
                Pin::New(fp)
            }
            _ => Pin::Known,
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

pub fn connect_pipe(command: &str, id: u64, tx: Sender<Ev>) -> Result<Conn, String> {
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
    std::thread::spawn(move || {
        let mut r = stderr;
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 || tx.send(Ev::Net(id, buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    Ok(Conn::Pipe { stdin, child })
}

/// Build the ssh command line for --ssh / #ssh. A trailing `:port` on the
/// destination becomes `-p port`.
pub fn ssh_command(dest: &str) -> String {
    let (target, port) = match dest.rsplit_once(':') {
        Some((t, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (t, Some(p)),
        _ => (dest, None),
    };
    let port_arg = port.map(|p| format!("-p {} ", p)).unwrap_or_default();
    format!(
        "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 {}{}",
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
            "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 play@mud.example.org"
        );
        assert_eq!(
            ssh_command("grib@127.0.0.1:2322"),
            "ssh -T -o BatchMode=yes -o ServerAliveInterval=30 -p 2322 grib@127.0.0.1"
        );
        assert!(ssh_command("a b").ends_with("'a b'"));
    }
}
