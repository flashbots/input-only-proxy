use anyhow::Result;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};

async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    println!("Accepted Unix socket connection");
    
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        
        total += n as u64;
        
        // Print the received data (if it's text)
        if let Ok(text) = std::str::from_utf8(&buffer[..n]) {
            print!("{}", text);
        } else {
            println!("Received {} bytes of binary data", n);
        }
    }
    
    println!("\nConnection closed. Total received: {} bytes", total);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let socket_path = "/tmp/test_input.sock"; // Use /tmp for testing
    
    // Remove existing socket if it exists
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }
    
    // Create Unix socket listener
    let listener = UnixListener::bind(socket_path)?;
    println!("Unix socket listener started at: {}", socket_path);
    println!("Run the proxy with: --unix-socket {}", socket_path);
    
    // Accept connections
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("Error handling connection: {}", e);
            }
        });
    }
}
