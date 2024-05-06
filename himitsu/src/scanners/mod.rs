mod regex;

use std::collections::HashSet;

use regex::RegexSystem;
use serde_derive::{Deserialize, Serialize};

use ring::digest::{digest, SHA256};

pub type ScanResults = HashSet<ScanResult>;

#[derive(Deserialize)]
pub struct Scanner {
    /// The regex system data generator which finds secrets by applying
    /// a suite of regexes to the input
    regex: RegexSystem,
    /// An optional list of hashes which if an output from a data generator matches,
    /// will not be returned as a finding.
    allowlist: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ScanResult {
    pub system: String,
    pub name: String,
    pub value: String,
    pub value_hash: String,
}

impl ScanResult {
    pub fn new(system: &str, name: &str, value: &str) -> Self {
        Self {
            system: system.to_string(),
            name: name.to_string(),
            value: value.to_string(),
            value_hash: hex::encode(digest(&SHA256, value.as_bytes())),
        }
    }
}

trait System {
    fn scan(&self, data: &str) -> ScanResults;
}

impl Scanner {
    pub fn default() -> Self {
        Self {
            regex: RegexSystem::default(),
            allowlist: None,
        }
    }

    pub fn scan(&self, data: &str) -> ScanResults {
        let results = self.regex.scan(data);

        if let Some(allowlist) = &self.allowlist {
            results
                .into_iter()
                .filter(|result| !allowlist.contains(&result.value_hash))
                .collect()
        } else {
            results
        }
    }
}
