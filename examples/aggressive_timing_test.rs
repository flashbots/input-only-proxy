use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const AUTH_SUCCESS: u8 = 0x01;
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

async fn load_private_key(path: &Path) -> Result<SigningKey> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read private key")?;
    
    if contents.contains("BEGIN OPENSSH PRIVATE KEY") {
        use ssh_key::PrivateKey;
        let ssh_key = PrivateKey::from_openssh(&contents)
            .context("Failed to parse OpenSSH private key")?;
        
        let ed_key = ssh_key
            .key_data()
            .ed25519()
            .context("Key is not Ed25519")?;
        
        return Ok(SigningKey::from_bytes(&ed_key.private.to_bytes()));
    }
    
    let key_bytes = hex::decode(contents.trim())
        .context("Failed to decode hex private key")?;
    
    if key_bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes");
    }
    
    Ok(SigningKey::from_bytes(&key_bytes.try_into().unwrap()))
}

async fn authenticate(stream: &mut TcpStream, signing_key: &SigningKey) -> Result<()> {
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).await?;
    let signature: Signature = signing_key.sign(&challenge);
    stream.write_all(&signature.to_bytes()).await?;
    let mut response = [0u8; 1];
    stream.read_exact(&mut response).await?;
    
    if response[0] == AUTH_SUCCESS {
        println!("Authentication successful");
        Ok(())
    } else {
        anyhow::bail!("Authentication failed")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <server:port> <private-key-file>", args[0]);
        eprintln!("This sends large chunks rapidly to overwhelm buffers");
        std::process::exit(1);
    }
    
    let server_addr = &args[1];
    let key_path = Path::new(&args[2]);
    
    let signing_key = load_private_key(key_path).await?;
    println!("Loaded private key");
    
    let mut stream = TcpStream::connect(server_addr).await?;
    println!("Connected to {}", server_addr);
    
    authenticate(&mut stream, &signing_key).await?;
    
    // Create 1MB of data
    let chunk_data = vec![b'X'; CHUNK_SIZE];
    
    println!("Sending {} x 1MB chunks rapidly...", 20);
    println!("This should fill buffers and reveal timing differences");
    
    for i in 0..20 {
        let start = Instant::now();
        stream.write_all(&chunk_data).await?;
        stream.flush().await?; // Force send
        let write_time = start.elapsed();
        
        println!("1MB Chunk {}: Write took {:?}", i, write_time);
        
        // Send chunks rapidly (no delay)
        if write_time > Duration::from_millis(100) {
            println!("  ↑ SLOW WRITE - buffer likely full, waiting for consumer");
        }
    }
    
    println!("Done. Look for slow writes above - those indicate timing leakage.");
    Ok(())
}