#[macro_use]
extern crate log;

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use himitsu::message::{HimitsuMessage, HimitsuResponse};

#[tokio::main]
async fn main() {
    debug!("Welcome To Himitsu Shim");

    // Himitsu Bypass Block
    let block_bypass = std::env::var("HBB").map(|x| x.len() > 0).unwrap_or(false);
    
    let diff = io::read_to_string(io::stdin()).unwrap();

    let mut stream = match UnixStream::connect("/tmp/himitsu.sock").await {
        Ok(stream) => stream,
        Err(e) => {
            println!("Failed to connect to Himitsu: {}", e);
            if block_bypass {
                std::process::exit(0);
            } else {
                std::process::exit(2);
            }   
        }
    };

    // Create a message to send to the local Himitsu handler
    let scan_message = HimitsuMessage::ScanCodeDiff {diff};
    let scan_message = serde_json::to_string(&scan_message).unwrap();

    stream.write_u32(scan_message.len() as u32).await.unwrap();
    stream.write_all(scan_message.as_bytes()).await.unwrap();

    let response_length = stream.read_u32().await.unwrap();
    let mut buf = vec![0; response_length as usize];
    stream.read_exact(&mut buf).await.unwrap();

    let response: HimitsuResponse = serde_json::from_slice(&buf).unwrap();

    let return_code = match response {
        HimitsuResponse::Clean => {
            println!("Himitsu Found No Secrets");
            0
        }
        HimitsuResponse::SecretsFound(secrets) => {
            for secret in secrets {
                println!("{} was found by system {} with contents: {}", secret.name, secret.system, secret.value);
            }
            1
        }
        HimitsuResponse::Error(e) => {
            println!("Error: {}", e);
            2
        }
    };

    // If the user has asked to bypass, we will return success no matter what
    if block_bypass {
        std::process::exit(0);
    } else {
        std::process::exit(return_code);
    }
}