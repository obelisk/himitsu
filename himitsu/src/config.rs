use base64::{prelude::BASE64_STANDARD, Engine};
use ring::{aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM, NONCE_LEN}, error::Unspecified};
use secrecy::{ExposeSecret, Secret};
use serde_derive::Deserialize;

use crate::{error::{HResult, HimitsuError}, scanners::Scanner};

#[derive(Deserialize)]
pub struct HimitsuConfiguration {
    pub scanner: Scanner,
}

impl From<reqwest::Error> for HimitsuError {
    fn from(err: reqwest::Error) -> Self {
        HimitsuError::WebConfigError(err)
    }
}

impl From<serde_json::Error> for HimitsuError {
    fn from(err: serde_json::Error) -> Self {
        HimitsuError::ConfigError(err)
    }
}

struct SingleNonceSequence(Option<Vec<u8>>);

impl NonceSequence for SingleNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce = self.0.as_ref().ok_or(Unspecified)?.clone();

        // Don't allow this to be used again
        self.0 = None;
        Nonce::try_assume_unique_for_key(&nonce)
    }
}


impl HimitsuConfiguration {
    pub fn default() -> Self {
        Self {
            scanner: Scanner::default(),
        }
    }

    fn decrypt_configuration(data: Vec<u8>, key: Secret<String>) -> HResult<Vec<u8>> {
        // Make sure the data is long enough to split off the nonce from the front
        if data.len() < NONCE_LEN {
            return Err(HimitsuError::CryptographyError("Invalid configuration".to_string()));
        }

        // Pull the nonce off the front of the encrypted data
        let (nonce, config_bytes) = data.split_at(NONCE_LEN);

        // Create a mutable copy of the configuration data without the nonce
        let mut in_out = config_bytes.to_vec();
        // Create the key for decrypting the configuration
        let unbound_key = UnboundKey::new(
            &AES_256_GCM, 
            hex::decode(key.expose_secret()).map_err(|_| HimitsuError::CryptographyError("Invalid key".to_string()))?.as_slice()
        )
            .map_err(|_| HimitsuError::CryptographyError("Invalid key".to_string()))?;

        // Create a new AEAD key for decrypting and verifying the authentication tag
        let mut opening_key = OpeningKey::new(unbound_key, SingleNonceSequence(Some(nonce.to_vec())));

        // Decrypt the data by passing in the associated data and the cypher text with the authentication tag appended
        let data = opening_key.open_in_place(Aad::empty(), &mut in_out).map_err(|_| HimitsuError::CryptographyError("Could not decrypt config".to_string()))?.into();

        Ok(data)
    }

    pub fn new_from_file(path: String) -> HResult<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let config: HimitsuConfiguration = serde_json::from_reader(reader)?;
        Ok(config)
    }

    pub fn new_from_b64_string(config: String, key: Option<Secret<String>>) -> HResult<Self> {
        let config = BASE64_STANDARD.decode(config.as_bytes()).map_err(|e| HimitsuError::EncodingError(e.to_string()))?;

        if let Some(key) = key {
            let data = Self::decrypt_configuration(config, key)?;
            Ok(serde_json::from_slice(&data)?)
         } else {
           Ok(serde_json::from_slice(&config)?)
         }
    }

    pub fn new_from_url(url: String, key: Option<Secret<String>>) -> HResult<Self> {
        let config = reqwest::blocking::get(&url)?.text()?;
        // All configurations are encoded first
        let mut config = BASE64_STANDARD.decode(config.as_bytes()).map_err(|e| HimitsuError::EncodingError(e.to_string()))?;

        // If we were given a key, decrypt the configuration
        if let Some(key) = key {
           config = Self::decrypt_configuration(config, key)?;
        }

        // Convert the decrypted data into a string we can deserialize
        let config = String::from_utf8(config.to_vec()).map_err(|e| HimitsuError::EncodingError(e.to_string()))?;

        let config: HimitsuConfiguration = serde_json::from_str(&config)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_from_b64_string() {
        const EXAMPLE_CONFIG: &str = concat!(
            "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");

        let config = HimitsuConfiguration::new_from_b64_string(EXAMPLE_CONFIG.to_string(), Some(Secret::new("0000000000000000000000000000000000000000000000000000000000000000".to_string())));
        
        if let Err(e) = config.as_ref() {
            println!("Error: {:?}", e);
        }
        assert_eq!(config.is_ok(), true);
    }
}