use std::{env, io::Read};

use base64::{prelude::BASE64_STANDARD, Engine};
use ring::{aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN}, error::Unspecified, rand::{SecureRandom, SystemRandom}};


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

fn new_single_nonce_sequence(rand: &SystemRandom) -> (Vec<u8>, SingleNonceSequence) {
    let mut nonce_bytes = vec![0; NONCE_LEN];
    rand.fill(&mut nonce_bytes).unwrap();

    (nonce_bytes.clone(), SingleNonceSequence(Some(nonce_bytes)))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config_path = args.get(1).map(|x| x.to_owned()).unwrap();

    let file = std::fs::File::open(config_path).unwrap();
    let mut in_out: Vec<u8> = vec![];
    std::io::BufReader::new(file).read_to_end(&mut in_out).unwrap();

    // Create a new instance of SystemRandom to be used as the single source of entropy
    let rand = SystemRandom::new();

    let (mut nonce, nonce_sequence) = new_single_nonce_sequence(&rand);

    let key = env::var("HIMITSU_KEY").unwrap();
    let key_bytes = hex::decode(key).unwrap();

    if key_bytes.len() != AES_256_GCM.key_len() {
        panic!("Key must be {} bytes long", AES_256_GCM.key_len());
    }

    // Create a new AEAD key without a designated role or nonce sequence
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();

    // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
    // The SealingKey can be used multiple times, each time a new nonce will be used
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    // Encrypt the data with AEAD using the AES_256_GCM algorithm
    let tag = sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut in_out).unwrap();

    nonce.append(&mut in_out);
    nonce.append(&mut tag.as_ref().to_vec());
    println!("Encrypted Configuration");
    println!("-----------------------");
    println!("{}", BASE64_STANDARD.encode(&nonce));
}