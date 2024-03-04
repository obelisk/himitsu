use serde_derive::Deserialize;

use crate::scanners::Scanner;

#[derive(Deserialize)]
pub struct HimitsuConfiguration {
    pub scanner: Scanner,
}

impl HimitsuConfiguration {
    pub fn default() -> Self {
        Self {
            scanner: Scanner::default(),
        }
    }

    pub fn new_from_file(path: String) -> Result<Self, std::io::Error> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let config: HimitsuConfiguration = serde_json::from_reader(reader)?;
        Ok(config)
    }
}
