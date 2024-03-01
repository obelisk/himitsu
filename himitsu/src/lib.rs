pub mod config;
mod error;
pub mod ffi;
mod handler;
pub mod message;
mod scanners;

pub use scanners::ScanResults;

use error::HResult;
use error::HimitsuError;
use tokio::runtime::Handle;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

#[macro_use]
extern crate log;

use std::env;
use std::process;

pub struct HimitsuInstance {
    term_sender: Sender<()>,
    handle: JoinHandle<()>,
}

impl HimitsuInstance {
    // Send the termination message and then wait for
    // Himitsu to shut down.
    pub async fn stop(self) {
        let _ = self.term_sender.send(()).await;
        let _ = self.handle.await;
    }

    pub async fn join(self) {
        let _ = self.handle.await;
    }
}

pub fn start_himitsu(
    runtime: Handle,
    socket_path: Option<String>,
    configuration: config::HimitsuConfiguration,
) -> HResult<HimitsuInstance> {
    let _ = env_logger::try_init();

    let socket_path = if let Some(path) = socket_path {
        path
    } else {
        let mut socket = env::temp_dir();
        socket.push(format!("himitsu.{}", process::id()));
        socket.to_string_lossy().to_string()
    };

    debug!("Starting Himitsu at: {socket_path}");

    let (term_sender, term_receiver) = tokio::sync::mpsc::channel::<()>(1);

    let handler = handler::HimitsuHandler::new(configuration);

    let handle = runtime.spawn(async move {
        handler::run(handler, socket_path, term_receiver).await;
    });

    Ok(HimitsuInstance {
        term_sender,
        handle,
    })
}
