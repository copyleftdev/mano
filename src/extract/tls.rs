use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use x509_parser::prelude::*;
use tracing::debug;

pub struct TlsInfo {
    pub subject_cn: Vec<String>,
    pub subject_an: Vec<String>,
    pub issuer: String,
}

/// Grab TLS certificate info from a host:port.
pub async fn grab_tls(host: &str, port: u16) -> Option<TlsInfo> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string()).ok()?;

    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&addr),
    ).await.ok()?.ok()?;

    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect(server_name, tcp),
    ).await.ok()?.ok()?;

    let (_, conn) = tls.get_ref();
    let certs = conn.peer_certificates()?;
    if certs.is_empty() {
        return None;
    }

    let (_, cert) = X509Certificate::from_der(certs[0].as_ref()).ok()?;

    let mut subject_cn = Vec::new();
    for attr in cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            subject_cn.push(cn.to_string());
        }
    }

    let mut subject_an = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                subject_an.push(dns.to_string());
            }
        }
    }

    let issuer = cert.issuer().iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_string();

    debug!(host = host, cn = ?subject_cn, san_count = subject_an.len(), "TLS grabbed");

    Some(TlsInfo {
        subject_cn,
        subject_an,
        issuer,
    })
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
