/*
 * Timing-Isolated Secure Input Proxy
 * 
 * PURPOSE: Prevent timing side-channel attacks where data consumption patterns
 * could leak information about sensitive orderflow data.
 * 
 * SECURITY MODEL: 
 * - External client sends sensitive orderflow data
 * - Data consumption speed variations could signal information
 * - Observer monitoring TCP timing could extract encoded data
 * - This proxy isolates TCP timing from consumption behavior
 * 
 * HOW IT WORKS:
 * 1. TCP Reader: Reads from client as fast as possible -> unbounded channel
 * 2. Unix Writer: Reads from channel -> writes to container at variable pace  
 * 3. Channel acts as timing isolation buffer - TCP never waits for container
 */

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use rand::RngCore;
use ssh_key::PublicKey;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const CHALLENGE_SIZE: usize = 32;
const READ_BUFFER_SIZE: usize = 64 * 1024; // 64KB chunks

#[derive(Parser)]
#[clap(about = "Timing-isolated proxy preventing timing-based attacks")]
struct Config {
    #[clap(long, default_value = "0.0.0.0:27017")]
    listen: SocketAddr,

    #[clap(long, default_value = "/persistent/input/input.sock")]
    unix_socket: PathBuf,

    #[clap(long, default_value = "/etc/searcher_key")]
    pubkey_file: PathBuf,

    #[clap(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,
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

/// Ed25519 challenge-response authentication 
async fn authenticate_client(stream: &mut TcpStream, pubkey: &VerifyingKey) -> Result<()> {
    // Send random challenge
    let mut challenge = [0u8; CHALLENGE_SIZE];
    rand::rng().fill_bytes(&mut challenge);
    stream.write_all(&challenge).await?;

    // Read signature response
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    stream.read_exact(&mut signature_bytes).await?;
    let signature = Signature::from_bytes(&signature_bytes);

    // Verify signature
    match pubkey.verify(&challenge, &signature) {
        Ok(()) => {
            stream.write_all(&[1]).await?; // Success
            Ok(())
        }
        Err(_) => {
            stream.write_all(&[0]).await?; // Failure  
            bail!("Authentication failed - invalid signature")
        }
    }
}

/// Security check: ensure path is actually a Unix socket
async fn verify_unix_socket(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(()); // Will be created by container
    }

    let metadata = tokio::fs::metadata(path).await?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            bail!("Security violation: {} exists but is not a Unix socket", path.display());
        }
    }
    
    Ok(())
}

/// Connect to Unix socket with timeout
async fn connect_to_container(socket_path: &Path) -> Result<UnixStream> {
    verify_unix_socket(socket_path).await?;
    
    let timeout = std::time::Duration::from_secs(10);
    tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .context("Timeout connecting to container socket")?
        .with_context(|| format!("Failed to connect to: {}", socket_path.display()))
}

/// Fast TCP reader - never blocks regardless of consumption speed
async fn tcp_to_channel_reader(mut tcp_stream: TcpStream, sender: mpsc::UnboundedSender<Vec<u8>>) -> Result<u64> {
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];
    let mut total_bytes = 0u64;
    
    loop {
        let bytes_read = tcp_stream.read(&mut buffer).await?;
        
        if bytes_read == 0 {
            break; // Client disconnected
        }
        
        total_bytes += bytes_read as u64;
        
        // Send to channel (never blocks - critical for timing isolation)
        let chunk = buffer[..bytes_read].to_vec();
        if sender.send(chunk).is_err() {
            warn!("Channel receiver dropped - stopping TCP reader");
            break;
        }
        
        // Progress logging for large transfers
        if total_bytes % (100 * 1024 * 1024) == 0 {
            info!("Received {}MB from client", total_bytes / (1024 * 1024));
        }
    }
    
    Ok(total_bytes)
}

/// Unix writer - forwards data at container's consumption speed
/// Consumption speed variations DO NOT affect TCP timing due to unbounded channel
async fn channel_to_unix_writer(mut receiver: mpsc::UnboundedReceiver<Vec<u8>>, mut unix_stream: UnixStream) -> Result<u64> {
    let mut total_bytes = 0u64;
    
    // Forward all data from channel to Unix socket
    // Container can process at any speed without affecting TCP timing
    while let Some(chunk) = receiver.recv().await {
        unix_stream.write_all(&chunk).await
            .context("Failed to write to container")?;
            
        total_bytes += chunk.len() as u64;
        
        if total_bytes % (100 * 1024 * 1024) == 0 {
            info!("Forwarded {}MB to container", total_bytes / (1024 * 1024));
        }
    }
    
    Ok(total_bytes)
}

/// Main data forwarding with timing isolation
async fn forward_with_timing_isolation(tcp_stream: TcpStream, unix_socket: &Path) -> Result<()> {
    // Connect to container
    let unix_stream = connect_to_container(unix_socket).await?;
    
    // Create unbounded channel - THIS IS THE CRITICAL SECURITY COMPONENT
    // Unbounded = TCP reader never waits for container consumption speed
    let (sender, receiver) = mpsc::unbounded_channel::<Vec<u8>>();
    
    info!("Starting timing-isolated data forwarding");
    
    // Spawn both tasks concurrently
    let tcp_task = tokio::spawn(tcp_to_channel_reader(tcp_stream, sender));
    let unix_task = tokio::spawn(channel_to_unix_writer(receiver, unix_stream));
    
    // Wait for both to complete
    let (tcp_result, unix_result) = tokio::join!(tcp_task, unix_task);
    
    let bytes_received = tcp_result.context("TCP reader failed")??;
    let bytes_forwarded = unix_result.context("Unix writer failed")??;
    
    info!("Transfer complete: {}MB received, {}MB forwarded", 
          bytes_received / (1024 * 1024), 
          bytes_forwarded / (1024 * 1024));
    
    if bytes_received != bytes_forwarded {
        warn!("Byte count mismatch - possible channel overflow during transfer");
    }
    
    Ok(())
}

async fn handle_connection(stream: TcpStream, pubkey: VerifyingKey, unix_socket: PathBuf) -> Result<()> {
    let client_addr = stream.peer_addr()?;
    info!("Client connected: {}", client_addr);
    
    // Authenticate first
    let mut auth_stream = stream;
    authenticate_client(&mut auth_stream, &pubkey).await
        .with_context(|| format!("Authentication failed for {}", client_addr))?;
    
    info!("Client authenticated: {}", client_addr);
    
    // Forward data with timing isolation
    forward_with_timing_isolation(auth_stream, &unix_socket).await
        .with_context(|| format!("Data forwarding failed for {}", client_addr))?;
    
    info!("Client disconnected: {}", client_addr);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&config.log_level)
        .init();

    info!("Secure Input Proxy v{} - Timing Isolation Enabled", env!("CARGO_PKG_VERSION"));
    info!("Purpose: Prevent timing-based attacks");
    info!("Listening: {}", config.listen);
    info!("Container socket: {}", config.unix_socket.display());

    // Load authentication key
    let pubkey = load_ed25519_pubkey(&config.pubkey_file).await?;
    info!("Loaded Ed25519 public key: {}", config.pubkey_file.display());

    // Create socket directory if needed
    if let Some(parent) = config.unix_socket.parent() {
        tokio::fs::create_dir_all(parent).await
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    // Start TCP server
    let listener = TcpListener::bind(config.listen).await?;
    info!("Proxy ready - timing attacks prevented by unbounded buffering");

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let pubkey = pubkey.clone();
                let unix_socket = config.unix_socket.clone();
                
                // Handle each connection in separate task
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, pubkey, unix_socket).await {
                        error!("Connection error: {:#}", e);
                    }
                });
            }
            Err(e) => error!("Failed to accept connection: {}", e),
        }
    }
}
