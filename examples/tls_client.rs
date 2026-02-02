use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <server:port> <client-cert.pem>", args[0]);
        eprintln!("Example: {} 127.0.0.1:27018 client-cert.pem", args[0]);
        eprintln!("");
        eprintln!("Generate client-cert.pem using:");
        eprintln!("  ./ssh_to_tls_cert.py ~/.ssh/id_ed25519 client-cert.pem");
        std::process::exit(1);
    }
    
    let server_addr = &args[1];
    let cert_path = &args[2];
    
    println!("Connecting to TLS proxy at {}", server_addr);
    println!("Using certificate: {}", cert_path);
    
    // Load certificate and private key from PEM file
    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {}", cert_path))?;
    let mut reader = BufReader::new(cert_file);
    
    // rustls-pemfile can parse both private keys and certificates from the same file
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;
    
    // Reopen file to read private key (reader position has moved)
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    
    let private_key = rustls_pemfile::private_key(&mut reader)
        .context("Failed to parse private key")?
        .context("No private key found in PEM file")?;
    
    // Configure TLS client with the loaded certificate
    let tls_config = rustls::ClientConfig::builder()
        .dangerous() // Required for self-signed certs
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(certs, private_key)?;
    
    let connector = TlsConnector::from(Arc::new(tls_config));
    
    // Connect to server
    let tcp_stream = TcpStream::connect(server_addr).await?;
    println!("TCP connection established");
    
    // Perform TLS handshake with client certificate
    let server_name = ServerName::try_from("localhost")?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;
    
    // The server is input-only and won't send data back, but attempting a read
    // with timeout will detect if the connection was closed due to auth failure
    use tokio::io::AsyncReadExt;
    let mut test_buf = [0u8; 1];
    
    // Try to read with a short timeout - if server rejected cert, connection will be closed
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(100),
        tls_stream.read(&mut test_buf)
    ).await {
        Ok(Ok(0)) => {
            // Read returned 0 bytes = connection closed
            eprintln!("TLS handshake failed - server rejected certificate (connection closed)");
            return Err(anyhow::format_err!("Server rejected client certificate"));
        },
        Ok(Ok(_)) => {
            // Shouldn't happen with input-only proxy
            println!("TLS handshake successful with client certificate!");
        },
        Ok(Err(e)) => {
            // Read error = connection problem
            eprintln!("TLS handshake failed - server rejected certificate: {}", e);
            return Err(e.into());
        },
        Err(_) => {
            // Timeout = connection is still open (good!)
            println!("TLS handshake successful with client certificate!");
        }
    }
    
    // Send test data
    println!("\nEnter data to send (or 'quit' to exit):");
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        stdin.read_line(&mut input)?;
        
        if input.trim() == "quit" {
            break;
        }
        
        tls_stream.write_all(input.as_bytes()).await?;
        println!("Sent {} bytes", input.len());
    }
    
    println!("Closing connection");
    Ok(())
}

// Accept any server certificate (for testing with self-signed certs)
// In production, verify the server's certificate properly
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        ]
    }
}