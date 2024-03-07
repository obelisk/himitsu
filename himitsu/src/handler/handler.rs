use tokio::sync::RwLock;

pub struct HimitsuHandler {
    configuration: RwLock<HimitsuConfiguration>,
    silence_next_check: RwLock<bool>,
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
            silence_next_check: RwLock::new(false),
        }
    }

    pub async fn update_configuration(&self) {
        self.configuration.write().await.refresh();
    }

    pub async fn silence_next_check(&self) {
        let mut snc = self.silence_next_check.write().await;
        *snc = true
    }

    async fn should_check_be_silent(&self) -> bool {
        let silence_check = { *self.silence_next_check.read().await };

        if silence_check {
            let mut snc = self.silence_next_check.write().await;
            *snc = false
        }

        return silence_check;
    }

    pub async fn handle_message(&self, request: HimitsuMessage) -> HResult<HimitsuResponse> {
        match request {
            HimitsuMessage::ScanCodeDiff { diff } => {
                let config = self.configuration.read().await;
                let results = config.scanner.scan(&diff);

                if results.is_empty() {
                    Ok(HimitsuResponse::Clean)
                } else if self.should_check_be_silent().await {
                    println!("We found secrets but we're not blocking the commit");
                    Ok(HimitsuResponse::SecretsFoundSilent(results))
                } else {
                    Ok(HimitsuResponse::SecretsFound(results))
                }
            }
        }
    }
}
