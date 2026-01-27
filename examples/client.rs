use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const AUTH_SUCCESS: u8 = 0x01;

async fn load_private_key(path: &Path) -> Result<SigningKey> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read private key")?;
    
    // Try to parse as SSH private key first
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
    
    // Otherwise try hex format
    let key_bytes = hex::decode(contents.trim())
        .context("Failed to decode hex private key")?;
    
    if key_bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes");
    }
    
    Ok(SigningKey::from_bytes(&key_bytes.try_into().unwrap()))
}

async fn authenticate(stream: &mut TcpStream, signing_key: &SigningKey) -> Result<()> {
    // Read challenge from server
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).await
        .context("Failed to read challenge")?;
    
    // Sign the challenge
    let signature: Signature = signing_key.sign(&challenge);
    
    // Send signature back
    stream.write_all(&signature.to_bytes()).await
        .context("Failed to send signature")?;
    
    // Read auth response
    let mut response = [0u8; 1];
    stream.read_exact(&mut response).await
        .context("Failed to read auth response")?;
    
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
        eprintln!("Example: {} 127.0.0.1:27017 private.key", args[0]);
        std::process::exit(1);
    }
    
    let server_addr = &args[1];
    let key_path = Path::new(&args[2]);
    
    // Load private key
    let signing_key = load_private_key(key_path).await?;
    println!("Loaded private key");
    
    // Connect to server
    let mut stream = TcpStream::connect(server_addr).await
        .context("Failed to connect to server")?;
    println!("Connected to {}", server_addr);
    
    // Authenticate
    authenticate(&mut stream, &signing_key).await?;
    
    // Send some test data
    let test_data = b"Hello from authenticated client!\n";
    stream.write_all(test_data).await?;
    println!("Sent {} bytes", test_data.len());
    
    // Send more data to simulate streaming
    for i in 0..5 {
        let data = format!("Data chunk {}\n", i);
        stream.write_all(data.as_bytes()).await?;
        println!("Sent: {}", data.trim());
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    
    println!("Done sending data");
    Ok(())
}