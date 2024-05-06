use std::{
    collections::HashSet,
    iter::Extend,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

pub enum SilenceSetting {
    // The system is not silenced and will return errors for secrets found
    NotSilenced,
    // Will silence the next check. Works well for Git Diffs
    SilenceSingle,
    // A silence set that has not started yet
    UpcomingSilenceSet { duration: u64 },
    // A silence set that is currently
    InSilenceSet { expires_at: u64 },
}

impl SilenceSetting {
    pub fn new() -> Self {
        Self::NotSilenced
    }

    pub fn silence_next_check(&mut self) {
        *self = SilenceSetting::SilenceSingle;
    }

    pub fn silence_next_check_set(&mut self, duration: u64) {
        *self = SilenceSetting::UpcomingSilenceSet { duration };
    }

    pub fn check_and_update(&mut self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0);

        match self {
            SilenceSetting::NotSilenced => false,
            SilenceSetting::SilenceSingle => {
                *self = SilenceSetting::NotSilenced;
                true
            }
            SilenceSetting::UpcomingSilenceSet { duration } => {
                *self = SilenceSetting::InSilenceSet {
                    expires_at: now + *duration,
                };
                true
            }
            SilenceSetting::InSilenceSet { expires_at } => {
                if now > *expires_at {
                    *self = SilenceSetting::NotSilenced;
                    false
                } else {
                    true
                }
            }
        }
    }
}

pub struct HimitsuHandler {
    configuration: RwLock<HimitsuConfiguration>,
    silence_next_check: Mutex<SilenceSetting>,
    last_found_secrets: RwLock<HashSet<ScanResult>>,
}

use crate::{
    config::HimitsuConfiguration,
    error::HResult,
    message::{HimitsuMessage, HimitsuResponse},
    scanners::ScanResult,
};

impl HimitsuHandler {
    pub fn new(configuration: HimitsuConfiguration) -> Self {
        Self {
            configuration: RwLock::new(configuration),
            silence_next_check: Mutex::new(SilenceSetting::new()),
            last_found_secrets: RwLock::new(HashSet::new()),
        }
    }

    pub async fn fetch_last_found_secrets(&self) -> HashSet<ScanResult> {
        self.last_found_secrets.read().await.clone()
    }

    pub async fn clear_found_secrets(&self) {
        self.last_found_secrets.write().await.clear()
    }

    pub async fn update_configuration(&self) {
        self.configuration.write().await.refresh();
    }

    pub async fn silence_next_check(&self) {
        if let Ok(mut snc) = self.silence_next_check.lock() {
            snc.silence_next_check();
        } else {
            error!("Failed to silence next check");
        }
    }

    pub async fn silence_next_check_set(&self, duration: u64) {
        self.silence_next_check
            .lock()
            .unwrap()
            .silence_next_check_set(duration);
    }

    async fn should_check_be_silent(&self) -> bool {
        self.silence_next_check.lock().unwrap().check_and_update()
    }

    pub async fn handle_message(&self, request: HimitsuMessage) -> HResult<HimitsuResponse> {
        match request {
            HimitsuMessage::ScanCodeDiff { diff } => {
                let config = self.configuration.read().await;
                let results = config.scanner.scan(&diff);
                self.last_found_secrets
                    .write()
                    .await
                    .extend(results.clone());

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
