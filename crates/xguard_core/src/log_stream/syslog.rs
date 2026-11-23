//! Syslog formatting (RFC 5424 and RFC 3164) and delivery over UDP, TCP and TLS (RFC 6587).

use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::Bytes;
use chrono::{NaiveDateTime, SecondsFormat, TimeZone, Utc};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket, lookup_host},
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

use super::{DEFAULT_APP_NAME, StoredConfig, SyslogFormat, SyslogFraming, SyslogOptions};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_BYTES: usize = 60 * 1024;
/// Informational severity (RFC 5424).
const SEVERITY_INFO: u8 = 6;
/// Enterprise ID placeholder for private structured data (`xguard@55555`).
const SD_ID: &str = "xguard@55555";

/// Parses one or more PEM-encoded X.509 certificates.
pub fn parse_certs(pem: &str) -> Option<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        certs.push(item.ok()?);
    }
    if certs.is_empty() { None } else { Some(certs) }
}

/// Parses a PEM-encoded private key (PKCS#8, RSA, or SEC1 EC).
pub fn parse_key(pem: &str) -> Option<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).ok()
}

fn default_hostname() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        let raw = std::env::var("HOSTNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .unwrap_or_else(|| "xguard".to_owned());
        sanitize_token(&raw, 255).unwrap_or_else(|| "xguard".to_owned())
    })
}

fn sanitize_token(value: &str, max_len: usize) -> Option<String> {
    let cleaned: String = value
        .trim()
        .bytes()
        .filter(|b| (33..=126).contains(b))
        .take(max_len)
        .map(char::from)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn escape_sd_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '"' | ']' => {
                out.push('\\');
                out.push(ch);
            }
            '\r' | '\n' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn extract_timestamp(entry: &Value) -> chrono::DateTime<Utc> {
    if let Some(ts) = entry.get("timestamp").and_then(Value::as_str) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            return dt.with_timezone(&Utc);
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
            return Utc.from_utc_datetime(&ndt);
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S%.f") {
            return Utc.from_utc_datetime(&ndt);
        }
    }
    Utc::now()
}

fn clean_msg(entry: &[u8]) -> String {
    let text = String::from_utf8_lossy(entry);
    text.trim_end_matches(['\r', '\n'])
        .replace(['\r', '\n'], " ")
}

/// Formats one activity log JSON line as an RFC 5424 or RFC 3164 syslog message.
#[must_use]
pub fn format_entry(entry: &[u8], options: &SyslogOptions) -> Vec<u8> {
    let pri = u16::from(options.facility) * 8 + u16::from(SEVERITY_INFO);
    let hostname = options
        .hostname
        .as_deref()
        .and_then(|h| sanitize_token(h, 255))
        .unwrap_or_else(|| default_hostname().to_owned());
    let app_name = options
        .app_name
        .as_deref()
        .and_then(|a| sanitize_token(a, 48))
        .unwrap_or_else(|| DEFAULT_APP_NAME.to_owned());
    let msg = clean_msg(entry);
    let parsed: Value = serde_json::from_str(&msg).unwrap_or(Value::Null);
    let ts = extract_timestamp(&parsed);

    match options.format {
        SyslogFormat::Rfc5424 => {
            let timestamp = ts.to_rfc3339_opts(SecondsFormat::Millis, true);
            let event_name = parsed
                .get("event")
                .and_then(Value::as_str)
                .and_then(|v| sanitize_token(v, 32));
            let msgid = event_name.as_deref().unwrap_or("-");

            let mut sd_params = Vec::new();
            if let Some(ev) = parsed.get("event").and_then(Value::as_str) {
                sd_params.push(format!("event=\"{}\"", escape_sd_value(ev)));
            }
            if let Some(user) = parsed.get("username").and_then(Value::as_str) {
                sd_params.push(format!("user=\"{}\"", escape_sd_value(user)));
            }
            if let Some(ip) = parsed.get("ip").and_then(Value::as_str) {
                sd_params.push(format!("ip=\"{}\"", escape_sd_value(ip)));
            }
            let sd = if sd_params.is_empty() {
                "-".to_owned()
            } else {
                format!("[{SD_ID} {}]", sd_params.join(" "))
            };
            format!("<{pri}>1 {timestamp} {hostname} {app_name} - {msgid} {sd} {msg}").into_bytes()
        }
        SyslogFormat::Rfc3164 => {
            let timestamp = ts.format("%b %e %H:%M:%S");
            format!("<{pri}>{timestamp} {hostname} {app_name}: {msg}").into_bytes()
        }
    }
}

/// Frames a formatted syslog message for TCP/TLS per RFC 6587.
#[must_use]
pub fn frame_tcp(message: &[u8], framing: SyslogFraming) -> Vec<u8> {
    match framing {
        SyslogFraming::OctetCounting => {
            let prefix = format!("{} ", message.len());
            let mut out = Vec::with_capacity(prefix.len() + message.len());
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(message);
            out
        }
        SyslogFraming::Newline => {
            let mut out = Vec::with_capacity(message.len() + 1);
            out.extend_from_slice(message);
            out.push(b'\n');
            out
        }
    }
}

#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_config(config: &StoredConfig) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("failed to initialize TLS: {err}"))?;

    let with_verifier = if !config.tls_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
    } else if let Some(ca_pem) = &config.cert {
        let certs = parse_certs(ca_pem).ok_or_else(|| "invalid CA certificate PEM".to_owned())?;
        let mut store = RootCertStore::empty();
        for cert in certs {
            store
                .add(cert)
                .map_err(|err| format!("invalid CA certificate: {err}"))?;
        }
        builder.with_root_certificates(store)
    } else {
        let mut store = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = store.add(cert);
        }
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(store)
    };

    let client_config = match (&config.client_cert, &config.client_key) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs =
                parse_certs(cert_pem).ok_or_else(|| "invalid client certificate PEM".to_owned())?;
            let key = parse_key(key_pem).ok_or_else(|| "invalid client private key".to_owned())?;
            with_verifier
                .with_client_auth_cert(certs, key)
                .map_err(|err| format!("invalid TLS client credentials: {err}"))?
        }
        _ => with_verifier.with_no_client_auth(),
    };
    Ok(Arc::new(client_config))
}

enum Transport {
    Udp,
    Tcp {
        stream: Option<TcpStream>,
    },
    Tls {
        connector: TlsConnector,
        server_name: ServerName<'static>,
        stream: Option<TlsStream<TcpStream>>,
    },
}

pub struct SyslogSender {
    host: String,
    port: u16,
    options: SyslogOptions,
    transport: Transport,
}

impl SyslogSender {
    pub fn new(config: &StoredConfig) -> Result<Self, String> {
        let url = Url::parse(&config.url).map_err(|err| format!("invalid syslog URL: {err}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| "syslog URL missing host".to_owned())?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let default_port = if url.scheme() == "tls" { 6514 } else { 514 };
        let port = url.port().unwrap_or(default_port);
        let options = config.syslog.clone().unwrap_or_default();

        let transport = match url.scheme() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp { stream: None },
            "tls" => {
                let tls_config = build_tls_config(config)?;
                let server_name = ServerName::try_from(host.clone())
                    .map_err(|_| format!("invalid TLS server name: {host}"))?;
                Transport::Tls {
                    connector: TlsConnector::from(tls_config),
                    server_name,
                    stream: None,
                }
            }
            other => return Err(format!("unsupported syslog transport: {other}")),
        };

        Ok(Self {
            host,
            port,
            options,
            transport,
        })
    }

    async fn resolve(&self) -> Result<SocketAddr, String> {
        let mut addrs = timeout(IO_TIMEOUT, lookup_host((self.host.as_str(), self.port)))
            .await
            .map_err(|_| "timed out resolving syslog host".to_owned())?
            .map_err(|err| format!("failed to resolve syslog host: {err}"))?;
        addrs
            .next()
            .ok_or_else(|| "syslog host resolved to no addresses".to_owned())
    }

    pub async fn send_batch(&mut self, lines: &[Bytes]) -> Result<(), String> {
        if lines.is_empty() {
            return Ok(());
        }
        let messages: Vec<Vec<u8>> = lines
            .iter()
            .map(|line| format_entry(line, &self.options))
            .collect();

        match &mut self.transport {
            Transport::Udp => {
                let addr = self.resolve().await?;
                let bind_addr = if addr.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let socket = UdpSocket::bind(bind_addr)
                    .await
                    .map_err(|err| format!("failed to open UDP socket: {err}"))?;
                for msg in &messages {
                    let payload = if msg.len() > MAX_UDP_BYTES {
                        &msg[..MAX_UDP_BYTES]
                    } else {
                        msg.as_slice()
                    };
                    timeout(IO_TIMEOUT, socket.send_to(payload, addr))
                        .await
                        .map_err(|_| "timed out sending UDP syslog packet".to_owned())?
                        .map_err(|err| format!("UDP syslog send failed: {err}"))?;
                }
                Ok(())
            }
            Transport::Tcp { .. } => {
                let mut wire = Vec::new();
                for msg in &messages {
                    wire.extend_from_slice(&frame_tcp(msg, self.options.framing));
                }
                self.send_tcp_wire(&wire).await
            }
            Transport::Tls { .. } => {
                let mut wire = Vec::new();
                for msg in &messages {
                    wire.extend_from_slice(&frame_tcp(msg, self.options.framing));
                }
                self.send_tls_wire(&wire).await
            }
        }
    }

    async fn send_tcp_wire(&mut self, wire: &[u8]) -> Result<(), String> {
        for attempt in 0..2 {
            let addr = match &self.transport {
                Transport::Tcp { stream: Some(_) } => None,
                _ => Some(self.resolve().await?),
            };
            let Transport::Tcp { stream } = &mut self.transport else {
                unreachable!()
            };
            if stream.is_none() {
                let connected = timeout(IO_TIMEOUT, TcpStream::connect(addr.unwrap()))
                    .await
                    .map_err(|_| "timed out connecting to TCP syslog".to_owned())?
                    .map_err(|err| format!("TCP syslog connect failed: {err}"))?;
                *stream = Some(connected);
            }
            let conn = stream.as_mut().unwrap();
            let res = timeout(IO_TIMEOUT, async {
                conn.write_all(wire).await?;
                conn.flush().await
            })
            .await;
            match res {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => {
                    *stream = None;
                    if attempt == 1 {
                        return Err(format!("TCP syslog write failed: {err}"));
                    }
                }
                Err(_) => {
                    *stream = None;
                    return Err("timed out writing to TCP syslog".to_owned());
                }
            }
        }
        Err("TCP syslog write failed".to_owned())
    }

    async fn send_tls_wire(&mut self, wire: &[u8]) -> Result<(), String> {
        for attempt in 0..2 {
            let addr = match &self.transport {
                Transport::Tls {
                    stream: Some(_), ..
                } => None,
                _ => Some(self.resolve().await?),
            };
            let Transport::Tls {
                connector,
                server_name,
                stream,
            } = &mut self.transport
            else {
                unreachable!()
            };
            if stream.is_none() {
                let tcp = timeout(IO_TIMEOUT, TcpStream::connect(addr.unwrap()))
                    .await
                    .map_err(|_| "timed out connecting to TLS syslog".to_owned())?
                    .map_err(|err| format!("TLS syslog connect failed: {err}"))?;
                let tls = timeout(IO_TIMEOUT, connector.connect(server_name.clone(), tcp))
                    .await
                    .map_err(|_| "timed out during syslog TLS handshake".to_owned())?
                    .map_err(|err| format!("syslog TLS handshake failed: {err}"))?;
                *stream = Some(tls);
            }
            let conn = stream.as_mut().unwrap();
            let res = timeout(IO_TIMEOUT, async {
                conn.write_all(wire).await?;
                conn.flush().await
            })
            .await;
            match res {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => {
                    *stream = None;
                    if attempt == 1 {
                        return Err(format!("TLS syslog write failed: {err}"));
                    }
                }
                Err(_) => {
                    *stream = None;
                    return Err("timed out writing to TLS syslog".to_owned());
                }
            }
        }
        Err("TLS syslog write failed".to_owned())
    }
}
