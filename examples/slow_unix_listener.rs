use anyhow::Result;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};

async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    println!("Accepted Unix socket connection");
    
    let mut buffer = [0u8; 1024];
    let mut total = 0u64;
    let mut chunk_count = 0u32;
    
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        
        total += n as u64;
        chunk_count += 1;
        
        // Simulate slow processing - every 10th chunk is processed slowly
        if chunk_count % 10 == 0 {
            println!("Chunk {}: Slow processing (2s delay)...", chunk_count);
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            println!("Chunk {}: Fast processing", chunk_count);
        }
        
        // Print the received data (if it's text)
        if let Ok(text) = std::str::from_utf8(&buffer[..n]) {
            print!("{}", text);
        }
    }
    
    println!("\nConnection closed. Total received: {} bytes in {} chunks", total, chunk_count);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let socket_path = "/tmp/test_input_slow.sock";
    
    // Remove existing socket if it exists
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }
    
    // Create Unix socket listener
    let listener = UnixListener::bind(socket_path)?;
    println!("Slow Unix socket listener started at: {}", socket_path);
    println!("This listener simulates variable processing speed");
    println!("Run proxy with: --unix-socket {}", socket_path);
    
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