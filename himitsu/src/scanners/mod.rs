mod regex;

use std::collections::HashSet;

use regex::RegexSystem;
use serde_derive::{Deserialize, Serialize};

pub type ScanResults = HashSet<ScanResult>;

#[derive(Deserialize)]
pub struct Scanner {
    regex: RegexSystem,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
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
