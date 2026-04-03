use crate::extract;
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Result of probing a single target.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub input: String,
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub status_code: u16,
    pub content_length: i64,
    pub content_type: String,
    pub title: String,
    pub server: String,
    pub technologies: Vec<String>,
    pub response_time_ms: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub redirect_location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body_hash_md5: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body_hash_sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_subject_cn: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_subject_an: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tls_issuer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cnames: Vec<String>,
    pub lines: usize,
    pub words: usize,
    pub failed: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl ProbeResult {
    pub fn failed(input: &str, error: String) -> Self {
        ProbeResult {
            input: input.to_string(),
            url: String::new(),
            scheme: String::new(),
            host: String::new(),
            port: 0,
            status_code: 0,
            content_length: -1,
            content_type: String::new(),
            title: String::new(),
            server: String::new(),
            technologies: Vec::new(),
            response_time_ms: 0,
            redirect_location: String::new(),
            body_hash_md5: String::new(),
            body_hash_sha256: String::new(),
            tls_subject_cn: Vec::new(),
            tls_subject_an: Vec::new(),
            tls_issuer: String::new(),
            ip: String::new(),
            cnames: Vec::new(),
            lines: 0,
            words: 0,
            failed: true,
            error,
        }
    }
}

/// Probe a single target with HTTPS-first fallback to HTTP.
pub async fn probe(
    client: &Client,
    input: &str,
    _follow_redirects: bool,
    extract_hashes: bool,
    _extract_tls: bool,
) -> ProbeResult {
    let (host, port, explicit_scheme) = parse_target(input);

    // Determine probe order: explicit scheme, or HTTPS-first with HTTP fallback
    let schemes: Vec<&str> = match explicit_scheme.as_deref() {
        Some("http") => vec!["http"],
        Some("https") => vec!["https"],
        _ => {
            if port == 80 {
                vec!["http", "https"]
            } else {
                vec!["https", "http"]
            }
        }
    };

    for scheme in &schemes {
        let url = if (scheme == &"https" && port == 443) || (scheme == &"http" && port == 80) {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        };

        debug!(url = %url, "probing");
        let start = Instant::now();

        let resp = match tokio::time::timeout(
            Duration::from_secs(10),
            client.get(&url).send(),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                debug!(url = %url, error = %e, "request failed");
                continue; // try next scheme
            }
            Err(_) => {
                debug!(url = %url, "timeout");
                continue;
            }
        };

        let elapsed = start.elapsed().as_millis() as u64;
        return build_result(input, &url, scheme, &host, port, resp, elapsed, extract_hashes).await;
    }

    ProbeResult::failed(input, "all schemes failed".into())
}

async fn build_result(
    input: &str,
    url: &str,
    scheme: &str,
    host: &str,
    port: u16,
    resp: Response,
    elapsed: u64,
    extract_hashes: bool,
) -> ProbeResult {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Read body
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeResult {
                input: input.to_string(),
                url: url.to_string(),
                scheme: scheme.to_string(),
                host: host.to_string(),
                port,
                status_code: status,
                content_length: -1,
                content_type,
                title: String::new(),
                server,
                technologies: Vec::new(),
                response_time_ms: elapsed,
                redirect_location: location,
                body_hash_md5: String::new(),
                body_hash_sha256: String::new(),
                tls_subject_cn: Vec::new(),
                tls_subject_an: Vec::new(),
                tls_issuer: String::new(),
                ip: String::new(),
                cnames: Vec::new(),
                lines: 0,
                words: 0,
                failed: false,
                error: format!("body read: {e}"),
            };
        }
    };

    let content_length = body_bytes.len() as i64;
    let body = String::from_utf8_lossy(&body_bytes);

    // Extract title from HTML
    let title = extract::title::extract_title(&body);

    // Line/word counts
    let lines = body.lines().count();
    let words = body.split_whitespace().count();

    // Technology fingerprinting from headers + body
    let technologies = extract::tech::detect_technologies(&server, &content_type, &body);

    // Hashes
    let (md5, sha256) = if extract_hashes {
        (
            extract::hash::md5_hex(&body_bytes),
            extract::hash::sha256_hex(&body_bytes),
        )
    } else {
        (String::new(), String::new())
    };

    ProbeResult {
        input: input.to_string(),
        url: url.to_string(),
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
        status_code: status,
        content_length,
        content_type,
        title,
        server,
        technologies,
        response_time_ms: elapsed,
        redirect_location: location,
        body_hash_md5: md5,
        body_hash_sha256: sha256,
        tls_subject_cn: Vec::new(),
        tls_subject_an: Vec::new(),
        tls_issuer: String::new(),
        ip: String::new(),
        cnames: Vec::new(),
        lines,
        words,
        failed: false,
        error: String::new(),
    }
}

/// Parse target into (host, port, scheme).
/// Handles: "example.com", "example.com:8080", "https://example.com", "http://1.2.3.4:8443"
fn parse_target(input: &str) -> (String, u16, Option<String>) {
    let input = input.trim();

    // Has scheme?
    if let Some(rest) = input.strip_prefix("https://") {
        let (host, port) = split_host_port(rest, 443);
        return (host, port, Some("https".into()));
    }
    if let Some(rest) = input.strip_prefix("http://") {
        let (host, port) = split_host_port(rest, 80);
        return (host, port, Some("http".into()));
    }

    // No scheme — extract host:port
    let (host, port) = split_host_port(input, 443);
    (host, port, None)
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    // Strip path
    let s = s.split('/').next().unwrap_or(s);

    if let Some(bracket_end) = s.find(']') {
        // IPv6: [::1]:port
        let host = &s[..=bracket_end];
        let rest = &s[bracket_end + 1..];
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }

    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            if let Ok(port) = port_str.parse::<u16>() {
                (host.to_string(), port)
            } else {
                (s.to_string(), default_port)
            }
        }
        None => (s.to_string(), default_port),
    }
}
