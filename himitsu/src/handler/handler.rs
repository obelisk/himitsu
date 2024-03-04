use tokio::sync::RwLock;

pub struct HimitsuHandler {
    configuration: RwLock<HimitsuConfiguration>,
}

use crate::{
    config::HimitsuConfiguration,
    error::HResult,
    message::{HimitsuMessage, HimitsuResponse},
};

impl HimitsuHandler {
    pub fn new(configuration: HimitsuConfiguration) -> Self {
        Self {
            configuration: RwLock::new(configuration),
        }
    }

    pub async fn update_configuration(&self, configuration: HimitsuConfiguration) {
        let mut config = self.configuration.write().await;
        *config = configuration;
    }

    pub async fn handle_message(&self, request: HimitsuMessage) -> HResult<HimitsuResponse> {
        match request {
            HimitsuMessage::ScanCodeDiff { diff } => {
                let config = self.configuration.read().await;
                let results = config.scanner.scan(&diff);

                if results.is_empty() {
                    Ok(HimitsuResponse::Clean)
                } else {
                    Ok(HimitsuResponse::SecretsFound(results))
                }
            }
        }
    }
}
