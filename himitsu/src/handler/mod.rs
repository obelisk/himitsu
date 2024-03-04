mod handler;

use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::sync::mpsc::Receiver;

use crate::config::HimitsuConfiguration;
use crate::message;
pub use handler::HimitsuHandler;

use crate::error::HResult;

async fn handle_client(handler: Arc<HimitsuHandler>, mut stream: UnixStream) -> HResult<()> {
    loop {
        let message = message::parse_incoming_message(&mut stream).await?;
        trace!("message: {:?}", message);
        let response = handler.handle_message(message).await?;
        trace!("handler: {:?}", response);
        message::serialize_and_send_response(response, &mut stream).await?;
    }
}

pub async fn run(
    handler: HimitsuHandler,
    socket_path: String,
    mut term_channel: Receiver<Option<HimitsuConfiguration>>,
) {
    println!("Starting Himitsu at: {}", socket_path);
    let listener = UnixListener::bind(socket_path).unwrap();
    let handler = Arc::new(handler);

    loop {
        select! {
            msg = term_channel.recv() => {
                match msg {
                    Some(Some(configuration)) => {
                        handler.update_configuration(configuration).await;
                    }
                    _ => {
                        println!("Received termination request. Exiting...");
                        return
                    }
                }
            },
            v = listener.accept() => {
                match v {
                    Ok(stream) => {
                        debug!("Got connection from: {:?}. Spawning task to handle.", stream.1);
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            match handle_client(handler, stream.0).await {
                                Ok(_) => {}
                                Err(e) => debug!("handler: {:?}", e),
                            }
                        });
                    }
                    Err(e) => {
                        // connection failed
                        println!("Encountered an error: {e}. Exiting...");
                        return;
                    }
                }
            },
        }
    }
}
