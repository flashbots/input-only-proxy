use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Load client certificate and private key from PEM file
fn load_client_credentials(cert_path: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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
    
    Ok((certs, private_key))
}

/// Load server certificate and create root certificate store
fn load_server_root_cert(server_cert_path: &str) -> Result<RootCertStore> {
    let server_cert_file = File::open(server_cert_path)
        .with_context(|| format!("Failed to open server certificate file: {}", server_cert_path))?;
    let mut server_reader = BufReader::new(server_cert_file);
    
    let server_certs = rustls_pemfile::certs(&mut server_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse server certificate")?;
    
    if server_certs.is_empty() {
        anyhow::bail!("No certificates found in server certificate file");
    }
    
    // Create root certificate store with the server's certificate
    let mut root_store = RootCertStore::empty();
    for cert in server_certs {
        root_store.add(cert)
            .context("Failed to add server certificate to trust store")?;
    }
    
    Ok(root_store)
}

/// Create TLS configuration with proper certificate verification
fn create_secure_tls_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    root_store: RootCertStore,
) -> Result<ClientConfig> {
    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, private_key)?)
}

/// Create TLS configuration that accepts any server certificate (for testing only)
fn create_insecure_tls_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(certs, private_key)?)
}

/// Verify TLS connection by attempting to read (input-only proxy won't send data)
async fn verify_tls_connection(
    tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<()> {
    let mut test_buf = [0u8; 1];
    
    // Try to read with a short timeout - if server rejected cert, connection will be closed
    match tokio::time::timeout(
        tokio::time::Duration::from_millis(100),
        tls_stream.read(&mut test_buf)
    ).await {
        Ok(Ok(0)) => {
            // Read returned 0 bytes = connection closed
            anyhow::bail!("Server rejected client certificate (connection closed)");
        },
        Ok(Ok(_)) => {
            // Shouldn't happen with input-only proxy
            println!("TLS handshake successful with client certificate!");
        },
        Ok(Err(e)) => {
            // Read error = connection problem
            anyhow::bail!("Server rejected certificate: {}", e);
        },
        Err(_) => {
            // Timeout = connection is still open (good!)
            println!("TLS handshake successful with client certificate!");
        }
    }
    Ok(())
}

/// Interactive loop to send data to the server
async fn interactive_send_loop(
    tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<()> {
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

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the default crypto provider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("Usage: {} <server:port> <client-cert.pem> [server-cert.pem]", args[0]);
        eprintln!("Example: {} 127.0.0.1:27018 client-cert.pem", args[0]);
        eprintln!("Example: {} 127.0.0.1:27018 client-cert.pem server-cert.pem", args[0]);
        eprintln!("");
        eprintln!("Generate client-cert.pem using:");
        eprintln!("  ./ssh_to_tls_cert.py ~/.ssh/id_ed25519 client-cert.pem");
        eprintln!("");
        eprintln!("Optional: Provide server-cert.pem for proper certificate verification");
        eprintln!("Without server-cert.pem, any server certificate will be accepted (testing only)");
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let cert_path = &args[2];
    let server_cert_path = args.get(3);

    println!("Connecting to TLS proxy at {}", server_addr);
    println!("Using client certificate: {}", cert_path);
    if let Some(server_cert) = server_cert_path {
        println!("Using server certificate: {} (secure mode)", server_cert);
    } else {
        println!("Warning: No server certificate provided - accepting any server cert (insecure)");
    }

    // Load client credentials
    let (certs, private_key) = load_client_credentials(cert_path)?;
    
    // Configure TLS based on whether server certificate is provided
    let tls_config = if let Some(server_cert_path) = server_cert_path {
        // Secure mode: verify server certificate
        let root_store = load_server_root_cert(server_cert_path)?;
        create_secure_tls_config(certs, private_key, root_store)?
    } else {
        // Testing mode: accept any server certificate
        create_insecure_tls_config(certs, private_key)?
    };

    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect to server
    let tcp_stream = TcpStream::connect(server_addr).await?;
    println!("TCP connection established");

    // Perform TLS handshake with client certificate
    let server_name = ServerName::try_from("localhost")?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Verify the connection is established
    verify_tls_connection(&mut tls_stream).await?;

    // Interactive loop to send data
    interactive_send_loop(&mut tls_stream).await?;
    
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
