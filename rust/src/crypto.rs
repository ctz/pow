use std::collections::BTreeMap;

extern crate rustc_serialize;
use rustc_serialize::json::{Json, ToJson, encode};
use rustc_serialize::{base64, json};
use rustc_serialize::base64::{ToBase64, FromBase64};

extern crate crypto;
use self::crypto::mac::{Mac, MacResult};
use self::crypto::hmac::Hmac;
use self::crypto::sha2::Sha256;
use self::crypto::symmetriccipher::SynchronousStreamCipher;
use self::crypto::chacha20::ChaCha20;
use self::crypto::hkdf::hkdf_expand;

extern crate fastpbkdf2;
use self::fastpbkdf2::pbkdf2_hmac_sha256;

use super::util::{get_random, memset, memcpy};

const PBKDF2_TYPE: &'static str = "pbkdf2-hmac-sha256";
const PBKDF2_ITERATIONS: u32 = 1 << 20;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 8;

/* Temporary storage for encryption keys for a specific site.
 * Has a drop() which clears keys material. */
#[derive(Debug)]
pub struct Keys {
  kconf: [u8; 32],
  kauth: [u8; 32]
}

impl Drop for Keys {
  fn drop(&mut self) {
    memset(&mut self.kconf, 0u8);
    memset(&mut self.kauth, 0u8);
  }
}

/* Medium-term storage of KDF inputs plus resulting master key.
 * Has a drop() which clears master key. */
#[derive(Debug,Clone)]
pub struct Secrets {
  salt: Vec<u8>,
  iterations: u32,

  // does master have a valid value?
  have_master: bool,

  // resulting master key
  master: [u8; 32]
}
  
impl ToJson for Secrets {
  fn to_json(&self) -> Json {
    let mut r = BTreeMap::new();
    r.insert("salt".to_string(), self.salt.to_base64(base64::STANDARD).to_json());
    r.insert("iter".to_string(), self.iterations.to_json());
    r.insert("kdf".to_string(), PBKDF2_TYPE.to_json());
    Json::Object(r)
  }
}

impl Drop for Secrets {
  fn drop(&mut self) {
    memset(&mut self.master, 0u8);
  }
}

impl Secrets {
  pub fn derive_key(&mut self, password: &[u8]) -> &mut Secrets {
    pbkdf2_hmac_sha256(password,
                       &self.salt[..],
                       self.iterations,
                       &mut self.master);

    self.have_master = true;

    self
  }

  pub fn keys_for_db(&self) -> Keys {
    self.keys_for_site("")
  }

  pub fn keys_for_site(&self, site: &str) -> Keys {
    assert!(self.have_master);

    let mut result = [0u8; 64];

    hkdf_expand(Sha256::new(),
                &self.master,
                site.as_bytes(),
                &mut result);

    let mut k = Keys {
      kconf: [0u8; 32],
      kauth: [0u8; 32]
    };
  
    memcpy(&mut k.kconf, &result[0..32]);
    memcpy(&mut k.kauth, &result[32..64]);

    k
  }

  pub fn fresh() -> Secrets {
    Secrets {
      iterations: PBKDF2_ITERATIONS,
      salt: get_random(SALT_LENGTH),
      have_master: false,
      master: [0u8; 32]
    }
  }

  pub fn decode(encoding: &Json) -> Secrets {
    let obj = encoding.as_object().unwrap();
    
    // check type
    let kdf = obj.get("kdf").unwrap().as_string().unwrap();
    assert!(kdf == PBKDF2_TYPE);

    let salt = obj.get("salt").unwrap().as_string().unwrap().from_base64().unwrap();
    
    Secrets {
      iterations: obj.get("iter").unwrap().as_u64().unwrap() as u32,
      salt: salt,
      have_master: false,
      master: [0u8; 32]
    }
  }
}

pub type Padding = fn(&mut Vec<u8>);

fn add_iso7816_padding(data: &mut Vec<u8>, boundary: usize) {
  data.push(0x80);
  while (data.len() % boundary) != 0 {
    data.push(0x00);
  }
}

pub fn add_padding_password(data: &mut Vec<u8>) {
  add_iso7816_padding(data, 64)
}

pub fn add_padding_database(data: &mut Vec<u8>) {
  add_iso7816_padding(data, 2048)
}

fn remove_iso7816_padding(data: &mut Vec<u8>) {
  /* removes iso7816 padding.  should leave message mostly untouched
   * on bad padding. */
  while data.len() != 0 {
    match data[data.len() - 1] {
      0x00 => { data.pop(); continue; },
      0x80 => { data.pop(); break; },
      _ => { break; }
    }
  }
}

pub fn encrypt_json(js: &Json, keys: &Keys, pad: Padding) -> Json {
  let plain_str = json::encode(&js).unwrap();
  let mut plain = plain_str.into_bytes();
  pad(&mut plain);
  
  let nonce = get_random(NONCE_LENGTH);
  let mut cipher = ChaCha20::new(&keys.kconf, &nonce[..]);
  let mut ciphertext = vec![0u8; plain.len()];
  cipher.process(&plain[..], &mut ciphertext[..]);

  let mut hmac = Hmac::new(Sha256::new(), &keys.kauth);
  hmac.input(&nonce[..]);
  hmac.input(&ciphertext);
  let tag = hmac.result();

  let mut r = BTreeMap::new();
  r.insert("nonce".to_string(), nonce.to_base64(base64::STANDARD).to_json());
  r.insert("tag".to_string(), tag.code().to_base64(base64::STANDARD).to_json());
  r.insert("cipher".to_string(), ciphertext.to_base64(base64::STANDARD).to_json());
  Json::Object(r)
}

pub fn decrypt_json(enc: &Json, keys: &Keys) -> Option<Json> {
  let obj = enc.as_object().unwrap();
  let nonce = obj.get("nonce").unwrap().as_string().unwrap().from_base64().unwrap();
  let ciphertext = obj.get("cipher").unwrap().as_string().unwrap().from_base64().unwrap();
  let tag = obj.get("tag").unwrap().as_string().unwrap().from_base64().unwrap();

  /* check tag */
  let mut hmac = Hmac::new(Sha256::new(), &keys.kauth);
  hmac.input(&nonce[..]);
  hmac.input(&ciphertext[..]);
  let actual_tag = hmac.result();

  if MacResult::new(&tag[..]) != actual_tag {
    return None;
  }

  /* looks ok, lets decrypt */
  let mut cipher = ChaCha20::new(&keys.kconf, &nonce[..]);
  let mut plain = vec![0u8; ciphertext.len()];
  cipher.process(&ciphertext[..], &mut plain[..]);
  remove_iso7816_padding(&mut plain);

  let plainstr = String::from_utf8(plain).unwrap();
  Some(Json::from_str(&plainstr).unwrap())
}

