#[macro_use]
extern crate log;

use clap::Parser;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use himitsu::message::{HimitsuMessage, HimitsuResponse};

use std::fs;

/// Accept paths to files to scan for secrets
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    path: Vec<String>,
}

enum Errors {
    CannotFindHomeDir = 1,
    HimitsuConnectionFailure,
    FileReadError,
    SecretsFound,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let socket = match home::home_dir() {
        Some(mut path) => {
            path.push("Library/Group Containers/5QYJ6C8ZNT.PassportControl/himitsuSocket");
            path.to_str().unwrap().to_string()
        }
        None => {
            error!("Failed to find home directory");
            std::process::exit(Errors::CannotFindHomeDir as i32);
        }
    };

    let mut stream = match UnixStream::connect(&socket).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to Himitsu: {}. Socket Path: {socket}", e);
            std::process::exit(Errors::HimitsuConnectionFailure as i32);
        }
    };

    let mut found = false;
    for path in args.path {
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) => {
                error!("Failed to read [{path}]: {}", e);
                std::process::exit(Errors::FileReadError as i32);
            }
        };

        // Create a message to send to the local Himitsu handler
        let scan_message = HimitsuMessage::ScanCodeDiff { diff: contents };
        let scan_message = serde_json::to_string(&scan_message).unwrap();

        stream.write_u32(scan_message.len() as u32).await.unwrap();
        stream.write_all(scan_message.as_bytes()).await.unwrap();

        let response_length = stream.read_u32().await.unwrap();
        let mut buf = vec![0; response_length as usize];
        stream.read_exact(&mut buf).await.unwrap();

        let response: HimitsuResponse = serde_json::from_slice(&buf).unwrap();

        match response {
            HimitsuResponse::Clean => (),
            HimitsuResponse::SecretsFound(secrets) => {
                for secret in secrets {
                    println!(
                        "{} was found by system {} with contents: {}",
                        secret.name, secret.system, secret.value
                    );
                }
                found = true;
            }
            HimitsuResponse::SecretsFoundSilent(secrets) => {
                for secret in secrets {
                    println!(
                        "IGNORING THAT: {} was found by system {} with contents: {}",
                        secret.name, secret.system, secret.value
                    );
                }
            }
            HimitsuResponse::Error(e) => {
                println!("Error: {}", e);
            }
        };

        if found {
            std::process::exit(Errors::SecretsFound as i32);
        }
    }
}
