
use std::collections::BTreeMap;

extern crate time;

extern crate rand;
use rand::Rng;
use rand::os::OsRng;

extern crate rustc_serialize;
use rustc_serialize::json::{Json, ToJson, encode};
use rustc_serialize::{base64, json};
use rustc_serialize::base64::{ToBase64, FromBase64};

extern crate crypto;
use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;

extern crate fastpbkdf2;
use fastpbkdf2::pbkdf2_hmac_sha256;

const PBKDF2_ITERATIONS: u32 = 1 << 20;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 8;

fn get_random(len: usize) -> Vec<u8> {
  OsRng::new().unwrap().gen_iter::<u8>().take(len).collect()
}

struct Secrets {
  salt: Vec<u8>,
  iterations: u32,
  ke: Vec<u8>,
  ks: Vec<u8>
}
  
impl ToJson for Secrets {
  fn to_json(&self) -> Json {
    let mut r = BTreeMap::new();
    r.insert("salt".to_string(), self.salt.to_base64(base64::STANDARD).to_json());
    r.insert("iter".to_string(), self.iterations.to_json());
    Json::Object(r)
  }
}

impl Secrets {
  fn derive_keys(&mut self, password: &[u8]) -> &mut Secrets {
    let mut master = [0u8; 32];

    pbkdf2_hmac_sha256(password,
                       &self.salt[..],
                       self.iterations,
                       &mut master);

    let mut derive = Hmac::new(Sha256::new(), &master);

    self.ke = Vec::new();
    self.ks = Vec::new();

    derive.input(b"encrypt\0");
    self.ke.extend(derive.result().code());
    
    derive.reset();
    derive.input(b"sign\0");
    self.ks.extend(derive.result().code());

    self
  }

  fn fresh() -> Secrets {
    Secrets {
      iterations: PBKDF2_ITERATIONS,
      salt: get_random(SALT_LENGTH),
      ks: Vec::new(),
      ke: Vec::new()
    }
  }

  fn decode(encoding: &Json) -> Secrets {
    let obj = encoding.as_object().unwrap();
    let salt = obj.get("salt").unwrap().as_string().unwrap().from_base64().unwrap();
    
    Secrets {
      iterations: obj.get("iter").unwrap().as_u64().unwrap() as u32,
      salt: salt,
      ks: Vec::new(),
      ke: Vec::new()
    }
  }
}

type Padding = fn(&mut Vec<u8>);

fn add_iso7816_padding(data: &mut Vec<u8>, boundary: usize) {
  data.push(0x80);
  while (data.len() % boundary) != 0 {
    data.push(0x00);
  }
}

fn add_padding_password(data: &mut Vec<u8>) {
  add_iso7816_padding(data, 64)
}

fn add_padding_database(data: &mut Vec<u8>) {
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

fn encrypt_json(js: &Json, sec: &Secrets, pad: Padding) -> Json {
  let plain_str = json::encode(&js).unwrap();
  let mut plain = plain_str.into_bytes();
  pad(&mut plain);
  
  let nonce = get_random(NONCE_LENGTH);
  let mut cipher = ChaCha20::new(&sec.ke[..], &nonce[..]);
  let mut ciphertext = vec![0u8; plain.len()];
  cipher.process(&plain[..], &mut ciphertext[..]);

  let mut hmac = Hmac::new(Sha256::new(), &sec.ks[..]);
  hmac.input(&nonce[..]);
  hmac.input(&ciphertext);
  let tag = hmac.result();

  let mut r = BTreeMap::new();
  r.insert("nonce".to_string(), nonce.to_base64(base64::STANDARD).to_json());
  r.insert("tag".to_string(), tag.code().to_base64(base64::STANDARD).to_json());
  r.insert("cipher".to_string(), ciphertext.to_base64(base64::STANDARD).to_json());
  Json::Object(r)
}

fn decrypt_json(enc: &Json, sec: &Secrets) -> Option<Json> {
  let obj = enc.as_object().unwrap();
  let nonce = obj.get("nonce").unwrap().as_string().unwrap().from_base64().unwrap();
  let ciphertext = obj.get("cipher").unwrap().as_string().unwrap().from_base64().unwrap();
  let tag = obj.get("tag").unwrap().as_string().unwrap().from_base64().unwrap();

  /* check tag */
  let mut hmac = Hmac::new(Sha256::new(), &sec.ks[..]);
  hmac.input(&nonce[..]);
  hmac.input(&ciphertext[..]);
  let actual_tag = hmac.result();

  if MacResult::new(&tag[..]) != actual_tag {
    return None;
  }

  /* looks ok, lets decrypt */
  let mut cipher = ChaCha20::new(&sec.ke[..], &nonce[..]);
  let mut plain = vec![0u8; ciphertext.len()];
  cipher.process(&ciphertext[..], &mut plain[..]);
  remove_iso7816_padding(&mut plain);

  let plainstr = String::from_utf8(plain).unwrap();
  Some(Json::from_str(&plainstr).unwrap())
}

fn utc_now() -> i64 {
  time::get_time().sec
}

const SITE_CIPHERS: &'static str = "ciphers";
const SITE_CREATED: &'static str = "created";
const SITE_UPDATED: &'static str = "updated";
const SITE_COMMENT: &'static str = "comment";
const SITE_URL: &'static str = "url";
const SITE_NAME: &'static str = "name";

struct Site {
  ciphers: BTreeMap<String, Json>,
  name: String,
  meta: Json
}

impl ToJson for Site {
  fn to_json(&self) -> Json {
    let mut r = self.meta.as_object().unwrap().clone();
    r.insert(SITE_CIPHERS.to_string(), self.ciphers.to_json());
    r.insert(SITE_NAME.to_string(), self.name.to_json());
    r.insert(SITE_UPDATED.to_string(), utc_now().to_json());
    Json::Object(r)
  }
}

impl Site {
  fn new(name: &str) -> Site {
    let mut s = Site {
      ciphers: BTreeMap::<String, Json>::new(),
      name: name.to_string(),
      meta: Json::Object(BTreeMap::new())
    };

    s.put_meta_i64(SITE_CREATED, utc_now());
    return s;
  }

  fn decode(enc: &Json) -> Site {
    let obj = enc.as_object().unwrap();

    Site {
      ciphers: obj.get(SITE_CIPHERS).unwrap().as_object().unwrap().clone(),
      name: obj.get(SITE_NAME).unwrap().as_string().unwrap().to_string(),
      meta: enc.clone()
    }
  }

  fn put_meta_i64(&mut self, key: &'static str, val: i64) {
    self.meta.as_object_mut().unwrap().insert(key.to_string(), val.to_json());
  }

  fn add_password(&mut self, kind: &str, password: &str, sec: &Secrets) {
    let cipher = encrypt_json(&password.to_string().to_json(),
                              sec,
                              add_padding_password);
    self.ciphers.insert(kind.to_string(), cipher);
  }

  fn has_password(&self, kind: &str) -> bool {
    self.ciphers.contains_key(&kind.to_string())
  }

  fn del_password(&mut self, kind: &str) {
    self.ciphers.remove(&kind.to_string());
  }

  fn get_password(&self, kind: &str, sec: &Secrets) -> Option<String> {
    let r = self.ciphers.get(&kind.to_string())
      .and_then(|ciphertext| decrypt_json(ciphertext, sec));

    match r {
      Some(pt) => Some(pt.as_string().unwrap().to_string()),
      None => None
    }
  }
}

struct Database {
  log: Vec<Json>,
  sites: BTreeMap<String, Site>,
  loaded_version: u32
}

impl Database {
  fn empty() -> Database {
    Database {
      log: Vec::new(),
      sites: BTreeMap::new(),
      loaded_version: 0
    }
  }

  fn encrypt(&self, sec: &Secrets) -> Json {
    let mut inner = BTreeMap::new();
    inner.insert("log".to_string(), self.log.to_json());
    inner.insert("sites".to_string(), self.sites.to_json());
    inner.insert("version".to_string(), (self.loaded_version + 1).to_json());

    let ciphertext = encrypt_json(&Json::Object(inner), sec, add_padding_database);

    let mut outer = BTreeMap::new();
    outer.insert("sec".to_string(), sec.to_json());
    outer.insert("cipher".to_string(), ciphertext);
    Json::Object(outer)
  }

  fn add_site(&mut self, site: Site) {
    self.sites.insert(site.name.clone(), site);
  }

  fn list_sites(&self) -> Vec<String> {
    self.sites.keys().cloned().collect()
  }

  fn has_site(&self, name: &str) -> bool {
    self.sites.contains_key(&name.to_string())
  }

  fn get_site<'a>(&'a self, name: &str) -> &'a Site {
    self.sites.get(&name.to_string()).unwrap()
  }

  fn del_site(&mut self, name: &str) {
    self.sites.remove(&name.to_string());
  }
}

fn main()
{
  /*
  let obj = Thing {
    data_int: 1,
    data_str: "butt".to_string(),
    data_vector: vec![1,2,3,4],
  };

  let enc = json::encode(&obj).unwrap();
  println!("thing {}", enc);

  let mut cipher = crypto::chacha20::ChaCha20::new(b"1234123412341234", b"12341234");
  let mut output = [0u8; 4];
  cipher.process(&"12341234".from_hex().unwrap()[..], &mut output);
  println!("cipher {}", output.to_hex());
  */

  let mut s = Secrets::fresh();
  let j = s.to_json();
  println!("thing {}", j);

  s.derive_keys(b"abc");

  let s2 = Secrets::decode(&j);
  println!("thing2 {}", s2.to_json());

  let x = encrypt_json(&j, &s, add_padding_password);
  println!("encrypt_json {}", x);

  let p = decrypt_json(&x, &s);
  println!("decrypt_json {}", p.unwrap());

  let st = Site::new("butt");
  let enc = st.to_json();
  println!("site {}", enc);
  let st2 = Site::decode(&enc);
  println!("site2 {}", st2.to_json());

  let mut db = Database::empty();
  db.add_site(st);
  println!("db {}", db.encrypt(&s));
}
