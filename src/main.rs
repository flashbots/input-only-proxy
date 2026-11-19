/*
 * TLS-Enabled Timing-Isolated Input Only Proxy (Improved)
 * 
 * Combines TLS encryption with all security features from main.rs:
 * - Ed25519-based mutual TLS authentication
 * - Timing isolation via unbounded channels
 * - Unix socket verification
 * - Connection timeouts and proper error handling
 * - Byte count verification
 */

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, SignatureScheme};
use ssh_key::PublicKey;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use x509_parser::prelude::*;

const READ_BUFFER_SIZE: usize = 64 * 1024; // 64KB chunks

#[derive(Parser)]
#[clap(about = "TLS-enabled timing-isolated proxy with ed25519 authentication")]
struct Config {
    /// Address and port to listen on for TLS connections
    #[clap(long, default_value = "0.0.0.0:27018")]
    listen: SocketAddr,

    /// Path to Unix socket to connect to container
    #[clap(long, default_value = "/persistent/input/input.sock")]
    unix_socket: PathBuf,

    /// Path to Ed25519 public key in SSH format for client cert verification
    #[clap(long, default_value = "/etc/searcher_key")]
    pubkey_file: PathBuf,

    #[clap(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Base path for server certificate and key files (will create .crt and .key files)
    #[clap(long, default_value = "/persistent/input-proxy")]
    cert_base_path: PathBuf,
}

/// Load Ed25519 public key from SSH format (handles both full and base64-only formats)
async fn load_ed25519_pubkey(path: &Path) -> Result<VerifyingKey> {
    let contents = tokio::fs::read_to_string(path).await
        .with_context(|| format!("Failed to read public key: {:?}", path))?;

    let contents = contents.trim();

    // Handle both formats:
    // 1. Full SSH: "ssh-ed25519 AAAAC3Nza..."
    // 2. Base64 only: "AAAAC3Nza..."
    let ssh_key_str = if !contents.starts_with("ssh-ed25519 ") && !contents.is_empty() {
        info!("Key file contains base64 only, adding ssh-ed25519 prefix");
        format!("ssh-ed25519 {}", contents)
    } else {
        contents.to_string()
    };

    let ssh_key = PublicKey::from_openssh(&ssh_key_str)
        .context("Invalid SSH public key format")?;

    let ed25519_key = ssh_key.key_data().ed25519()
        .context("Key is not Ed25519 - only Ed25519 keys supported")?;

    VerifyingKey::from_bytes(ed25519_key.as_ref())
        .context("Invalid Ed25519 key bytes")
}

/// Connect to Unix socket with timeout
async fn connect_to_container(socket_path: &Path) -> Result<UnixStream> {
    // Pin to inode
    let socket = File::options().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(socket_path)?;
    if !socket.metadata()?.file_type().is_socket() {
        bail!("Security violation: {} is not a Unix socket", socket_path.display());
    }

    let timeout = std::time::Duration::from_secs(10);
    tokio::time::timeout(timeout, UnixStream::connect(format!("/proc/self/fd/{}", socket.as_raw_fd())))
        .await
        .context("Timeout connecting to container socket")?
        .with_context(|| format!("Failed to connect to: {}", socket_path.display()))
}

/// Custom certificate verifier that checks ed25519 public key
#[derive(Debug)]
struct Ed25519CertVerifier {
    expected_pubkey: VerifyingKey,
}

impl Ed25519CertVerifier {
    fn new(pubkey: VerifyingKey) -> Arc<Self> {
        Arc::new(Self {
            expected_pubkey: pubkey,
        })
    }
}

impl ClientCertVerifier for Ed25519CertVerifier {
    fn offer_client_auth(&self) -> bool {
        true // Require client cert
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[] // We don't use traditional CA chains
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        // Extract the public key
        let public_key = cert.public_key();

        // Check if it's ed25519
        if public_key.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ));
        }

        // Extract raw ed25519 public key bytes (32 bytes)
        let raw_key = public_key.subject_public_key.as_ref();

        // Compare with our expected public key
        if raw_key.len() == 32 && raw_key == self.expected_pubkey.as_bytes() {
            info!("Client certificate validated successfully");
            Ok(ClientCertVerified::assertion())
        } else {
            warn!("Client certificate validation failed - pubkey mismatch");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Verify ed25519 signature during handshake
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ));
        }

        // Parse certificate to get public key
        let (_, x509_cert) = X509Certificate::from_der(cert.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        let public_key_bytes = x509_cert.public_key().subject_public_key.as_ref();
        if public_key_bytes.len() != 32 {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ));
        }

        // Verify signature using ed25519
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

        let signature = ed25519_dalek::Signature::from_slice(dss.signature())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

        verifying_key.verify_strict(message, &signature)
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Generate and save a self-signed certificate for the server
fn generate_and_store_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    use rcgen::CertificateParams;

    let mut params = CertificateParams::new(vec!["localhost".into()])?;
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = params.self_signed(&keypair)?;

    // Save certificate and key to separate files
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, keypair.serialize_pem())?;

    info!("Generated new server certificate: {:?}", cert_path);
    info!("Generated new server key: {:?}", key_path);

    Ok(())
}

/// Load certificate and key from separate PEM files
fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rustls_pemfile::{certs, private_key};

    // Load certificate
    let mut cert_reader = BufReader::new(File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {:?}", cert_path))?);
    let certs = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;

    if certs.is_empty() {
        bail!("No certificates found in file: {:?}", cert_path);
    }

    // Load private key
    let mut key_reader = BufReader::new(File::open(key_path)
        .with_context(|| format!("Failed to open key file: {:?}", key_path))?);
    let key = private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in file: {:?}", key_path))?;

    info!("Loaded server certificate from: {:?}", cert_path);
    info!("Loaded server key from: {:?}", key_path);

    Ok((certs, key))
}


/// Load existing certificate or generate new one
async fn load_or_generate_server_cert(
    cert_base_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Build the actual paths
    let cert_path = cert_base_path.with_extension("crt");
    let key_path = cert_base_path.with_extension("key");

    if cert_path.exists() && key_path.exists() {
        // Load existing certificate and key
        load_cert_and_key(&cert_path, &key_path)
    } else {
        // Create parent directory if needed
        if let Some(dir) = cert_path.parent() {
            tokio::fs::create_dir_all(dir).await
                .with_context(|| format!("Failed to create directory: {:?}", dir))?;
        }

        // Generate and store new certificate
        generate_and_store_cert(&cert_path, &key_path)?;

        // Load the newly generated files
        load_cert_and_key(&cert_path, &key_path)
    }
}

/// Fast TLS reader - never blocks regardless of consumption speed
async fn tls_to_channel_reader(
    mut tls_stream: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    sender: mpsc::UnboundedSender<Vec<u8>>
) -> Result<u64> {
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = tls_stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            break; // Client disconnected
        }

        total_bytes += bytes_read as u64;

        // Send to channel (never blocks - critical for timing isolation)
        // Don't alert sender when container closes connection
        let _ = sender.send(buffer[..bytes_read].to_vec());

        // Progress logging for large transfers
        if total_bytes % (100 * 1024 * 1024) == 0 {
            info!("Received {}MB from client", total_bytes / (1024 * 1024));
        }
    }

    Ok(total_bytes)
}

/// Unix writer - forwards data at container's consumption speed
/// Consumption speed variations DO NOT affect TLS/TCP timing due to unbounded channel
async fn channel_to_unix_writer(
    mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    unix_socket: PathBuf
) -> u64 {
    let mut unix_stream: Option<UnixStream> = None;
    let mut total_bytes = 0u64;
    let mut dropped_bytes = 0u64;

    while let Some(chunk) = receiver.recv().await {
        if unix_stream.is_none() {
            match connect_to_container(&unix_socket).await {
                Ok(stream) => {
                    if dropped_bytes > 0 {
                        info!("Reconnected to container after dropping {} bytes", dropped_bytes);
                        dropped_bytes = 0;
                    }
                    unix_stream = Some(stream);
                }
                Err(e) => {
                    if dropped_bytes == 0 {
                        warn!("Container unreachable, dropping data until it returns: {:#}", e);
                    }
                    dropped_bytes += chunk.len() as u64;
                    continue;
                }
            }
        }
        let Some(stream) = unix_stream.as_mut() else { continue };

        if let Err(e) = stream.write_all(&chunk).await {
            warn!("Write to container failed, reconnecting: {}", e);
            dropped_bytes += chunk.len() as u64;
            unix_stream = None;
            continue;
        }

        total_bytes += chunk.len() as u64;

        if total_bytes % (100 * 1024 * 1024) == 0 {
            info!("Forwarded {}MB to container", total_bytes / (1024 * 1024));
        }
    }

    total_bytes
}

/// Main data forwarding with timing isolation
async fn forward_with_timing_isolation(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    unix_socket: &Path
) -> Result<()> {
    let (tls_read, _) = tokio::io::split(tls_stream);

    // Create unbounded channel - THIS IS THE CRITICAL SECURITY COMPONENT
    // Unbounded = TLS reader never waits for container consumption speed
    let (sender, receiver) = mpsc::unbounded_channel::<Vec<u8>>();

    info!("Starting timing-isolated data forwarding (TLS encrypted)");

    // Spawn both tasks concurrently
    let tls_task = tokio::spawn(tls_to_channel_reader(tls_read, sender));
    let unix_task = tokio::spawn(channel_to_unix_writer(receiver, unix_socket.to_path_buf()));

    // Wait for both to complete
    let (tls_result, unix_result) = tokio::join!(tls_task, unix_task);

    let bytes_received = tls_result.context("TLS reader failed")??;
    let bytes_forwarded = unix_result.context("Unix writer failed")?;
    
    info!("Transfer complete: {}MB received, {}MB forwarded", 
          bytes_received / (1024 * 1024), 
          bytes_forwarded / (1024 * 1024));
    
    if bytes_received != bytes_forwarded {
        warn!("Byte count mismatch - {} bytes were not delivered to the container",
              bytes_received - bytes_forwarded);
    }

    Ok(())
}

/// Handle client connection with TLS and timing isolation
async fn handle_client(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    unix_path: PathBuf,
    client_addr: SocketAddr,
) -> Result<()> {
    info!("TLS connection established with {}", client_addr);

    // Forward data with timing isolation
    forward_with_timing_isolation(stream, &unix_path).await
        .with_context(|| format!("Data forwarding failed for {}", client_addr))?;

    info!("Client disconnected: {}", client_addr);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config = Config::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&config.log_level)
        .init();

    info!("TLS Input Only Proxy v{} - Timing Isolation Enabled", env!("CARGO_PKG_VERSION"));
    info!("Purpose: Prevent timing-based attacks with TLS encryption");
    info!("Listening on {}", config.listen);
    info!("Unix socket: {}", config.unix_socket.display());

    // Load ed25519 public key for client verification
    let pubkey = load_ed25519_pubkey(&config.pubkey_file).await?;
    info!("Loaded Ed25519 public key: {}", config.pubkey_file.display());

    // Create socket directory if needed
    if let Some(parent) = config.unix_socket.parent() {
        tokio::fs::create_dir_all(parent).await
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    // Load or generate server certificate
    let (cert_chain, key_der) = load_or_generate_server_cert(
        &config.cert_base_path
    ).await?;

    // Configure TLS with custom client cert verifier
    let verifier = Ed25519CertVerifier::new(pubkey);
    
    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key_der)?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Start TCP listener
    let listener = TcpListener::bind(config.listen).await?;
    info!("TLS proxy ready - timing attacks prevented by unbounded buffering");

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((tcp_stream, addr)) => {
                info!("New connection from {}", addr);

                let tls_acceptor = tls_acceptor.clone();
                let unix_path = config.unix_socket.clone();
                
                // Handle each connection in separate task
                tokio::spawn(async move {
                    // Perform TLS handshake with client certificate validation
                    match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = handle_client(tls_stream, unix_path, addr).await {
                                error!("Client handling error for {}: {:#}", addr, e);
                            }
                        }
                        Err(e) => {
                            warn!("TLS handshake failed for {}: {}", addr, e);
                        }
                    }
                });
            }
            Err(e) => error!("Failed to accept connection: {}", e),
        }
    }
}
