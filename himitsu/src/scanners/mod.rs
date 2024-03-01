mod regex;

use regex::RegexSystem;
use serde_derive::{Deserialize, Serialize};

pub type ScanResults = Vec<ScanResult>;

pub struct Scanner {
    regex: RegexSystem,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub system: String,
    pub name: String,
    pub value: String,
}

trait System {
    fn scan(&self, data: &str) -> ScanResults;
}

impl Scanner {
    pub fn default() -> Self {
        Self {
            regex: RegexSystem::default(),
        }
    }

    pub fn scan(&self, data: &str) -> ScanResults {
        self.regex.scan(data)
    }
}