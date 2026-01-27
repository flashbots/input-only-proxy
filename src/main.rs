use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use rand::RngCore;
use ssh_key::PublicKey;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tracing::{error, info, warn};

const CHALLENGE_LEN: usize = 32;
const BUFFER_SIZE: usize = 65536; // 64KB chunks - optimal for streaming large data

// Authentication protocol responses
const AUTH_SUCCESS: u8 = 0x01;
const AUTH_FAILURE: u8 = 0x00;

#[derive(Parser, Debug)]
#[clap(name = "secure-input-proxy")]
#[clap(about = "Secure TCP to Unix socket proxy with Ed25519 authentication")]
struct Args {
    #[clap(long, default_value = "0.0.0.0:27017")]
    listen: SocketAddr,

    #[clap(long, default_value = "/persistent/input/input.sock")]
    unix_socket: PathBuf,

    #[clap(long, default_value = "/etc/searcher_key")]
    pubkey_file: PathBuf,

    #[clap(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,
}

async fn load_pubkey(path: &Path) -> Result<VerifyingKey> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read public key from {:?}", path))?;
    
    let ssh_key = PublicKey::from_openssh(&contents)
        .context("Failed to parse OpenSSH public key")?;
    
    let ed_key = ssh_key
        .key_data()
        .ed25519()
        .context("Key is not Ed25519")?;
    
    VerifyingKey::from_bytes(ed_key.as_ref())
        .context("Invalid Ed25519 key")
}

async fn authenticate(stream: &mut TcpStream, pubkey: &VerifyingKey) -> Result<()> {
    // Step 1: Send random challenge to client
    let mut challenge = [0u8; CHALLENGE_LEN];
    rand::rng().fill_bytes(&mut challenge);
    stream.write_all(&challenge).await
        .context("Failed to send challenge")?;

    // Step 2: Read signature from client
    let mut sig_bytes = [0u8; SIGNATURE_LENGTH];
    stream
        .read_exact(&mut sig_bytes)
        .await
        .context("Failed to read signature")?;
    let sig = Signature::from_bytes(&sig_bytes);

    // Step 3: Verify signature and respond
    if pubkey.verify(&challenge, &sig).is_ok() {
        stream.write_all(&[AUTH_SUCCESS]).await?;
        Ok(())
    } else {
        stream.write_all(&[AUTH_FAILURE]).await?;
        bail!("Signature verification failed")
    }
}

async fn forward_to_unix(stream: &mut TcpStream, unix_path: &Path) -> Result<()> {
    // Security: Verify the path is actually a Unix socket (if it exists)
    if unix_path.exists() {
        let metadata = tokio::fs::metadata(unix_path)
            .await
            .with_context(|| format!("Failed to stat {:?}", unix_path))?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket() {
                bail!("Security error: Path exists but is not a Unix socket");
            }
        }
    }
    
    // Connect to Unix socket with timeout (prevents hanging on unresponsive socket)
    const CONNECT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);
    let mut unix_stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        UnixStream::connect(unix_path)
    )
    .await
    .context("Timeout connecting to Unix socket (socket unresponsive)")?
    .with_context(|| format!("Failed to connect to Unix socket {:?}", unix_path))?;
    
    // Buffer for streaming data - this doesn't limit total size, just chunk size
    let mut buf = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;
    
    // Stream data from TCP to Unix socket until TCP connection closes
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // TCP connection closed
        }
        
        // Forward chunk to Unix socket with write timeout
        const WRITE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(30);
        tokio::time::timeout(
            WRITE_TIMEOUT,
            unix_stream.write_all(&buf[..n])
        )
        .await
        .context("Timeout writing to Unix socket (socket not consuming data)")?
        .context("Failed to write to Unix socket")?;
        
        total_bytes += n as u64;
        
        // Log progress for large transfers (every 100MB)
        if total_bytes % (100 * 1024 * 1024) == 0 {
            info!("Forwarded {}MB", total_bytes / (1024 * 1024));
        }
    }
    
    info!("Transfer complete: {} bytes", total_bytes);
    Ok(())
}

async fn handle_client(
    mut stream: TcpStream,
    pubkey: VerifyingKey,
    unix_path: PathBuf,
) -> Result<()> {
    let addr = stream.peer_addr()?;
    info!("{}: connected", addr);
    
    // Authenticate once per connection
    if let Err(e) = authenticate(&mut stream, &pubkey).await {
        warn!("{}: auth failed: {}", addr, e);
        return Err(e);
    }
    info!("{}: authenticated", addr);

    // Forward all data from this authenticated connection
    // Client can keep sending data until they close the connection
    if let Err(e) = forward_to_unix(&mut stream, &unix_path).await {
        error!("{}: forward error: {}", addr, e);
        return Err(e);
    }
    
    info!("{}: disconnected", addr);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .init();

    info!("Starting secure-input-proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Protocol: Authenticate once, then stream unlimited data");

    // Load public key
    let pubkey = load_pubkey(&args.pubkey_file).await?;
    info!("Loaded Ed25519 public key from {:?}", args.pubkey_file);

    // Create Unix socket directory if needed
    if let Some(parent) = args.unix_socket.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    // Note: We don't remove existing Unix socket here because
    // this proxy connects TO a Unix socket (doesn't create one)
    // The container should be listening on this socket

    // Start TCP listener
    let listener = TcpListener::bind(args.listen).await?;
    info!("Listening on {}", args.listen);
    info!("Will forward to Unix socket: {:?}", args.unix_socket);

    loop {
        let (stream, _) = listener.accept().await?;
        let pk = pubkey.clone();
        let unix_path = args.unix_socket.clone();
        
        // Spawn handler for each connection
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, pk, unix_path).await {
                error!("Client handler error: {:#}", e);
            }
        });
    }
}