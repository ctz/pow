
use std::collections::BTreeMap;

extern crate time;

extern crate rustc_serialize;
use rustc_serialize::json::{Json, ToJson};

use super::crypto::{encrypt_json, decrypt_json, add_padding_password, add_padding_database};
use super::crypto::{Secrets};

fn utc_now() -> i64 {
  time::get_time().sec
}

const SITE_CIPHERS: &'static str = "ciphers";
const SITE_CREATED: &'static str = "created";
const SITE_UPDATED: &'static str = "updated";
const SITE_NAME: &'static str = "name";

#[derive(Debug,Clone)]
pub struct Site {
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
  pub fn new(name: &str) -> Site {
    let mut s = Site {
      ciphers: BTreeMap::<String, Json>::new(),
      name: name.to_string(),
      meta: Json::Object(BTreeMap::new())
    };

    s.put_meta_i64(SITE_CREATED, utc_now());
    return s;
  }

  pub fn decode(enc: &Json) -> Site {
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

  pub fn add_password(&mut self, kind: &str, password: &str, sec: &Secrets) {
    let keys = sec.keys_for_site(&self.name);
    let cipher = encrypt_json(&password.to_string().to_json(),
                              &keys,
                              add_padding_password);
    self.ciphers.insert(kind.to_string(), cipher);
  }

  pub fn is_empty(&self) -> bool {
    self.ciphers.len() == 0
  }

  pub fn has_password(&self, kind: &str) -> bool {
    self.ciphers.contains_key(&kind.to_string())
  }

  pub fn del_password(&mut self, kind: &str) {
    self.ciphers.remove(&kind.to_string());
  }

  pub fn list_kinds(&self) -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    for k in self.ciphers.keys() {
      ret.push(k.clone());
    }
    ret
  }

  pub fn get_password(&self, kind: &str, sec: &Secrets) -> Option<String> {
    let keys = sec.keys_for_site(&self.name);
    let r = self.ciphers.get(&kind.to_string())
      .and_then(|ciphertext| decrypt_json(ciphertext, &keys));

    match r {
      Some(pt) => Some(pt.as_string().unwrap().to_string()),
      None => None
    }
  }
}

#[derive(Debug,Clone)]
pub struct Database {
  sites: BTreeMap<String, Site>,
  loaded_version: u32
}

impl Database {
  pub fn empty() -> Database {
    Database {
      sites: BTreeMap::new(),
      loaded_version: 0
    }
  }

  pub fn encrypt(&self, sec: &Secrets) -> Json {
    let mut inner = BTreeMap::new();
    inner.insert("sites".to_string(), self.sites.to_json());
    inner.insert("version".to_string(), (self.loaded_version + 1).to_json());

    let keys = sec.keys_for_db();
    let ciphertext = encrypt_json(&Json::Object(inner), &keys, add_padding_database);

    let mut outer = BTreeMap::new();
    outer.insert("kdf".to_string(), sec.to_json());
    outer.insert("cipher".to_string(), ciphertext);
    Json::Object(outer)
  }

  pub fn decode(json: &Json) -> Database {
    let mut sites: BTreeMap<String, Site> = BTreeMap::new();
    let input = json.as_object().unwrap().get("sites").unwrap().as_object().unwrap();

    for (name, sitejson) in input {
      sites.insert(name.clone(), Site::decode(sitejson));
    }

    Database {
      sites: sites,
      loaded_version: json.as_object().unwrap().get("version").unwrap().as_u64().unwrap() as u32
    }
  }

  pub fn add_site(&mut self, site: Site) {
    self.sites.insert(site.name.clone(), site);
  }

  pub fn list_sites(&self) -> Vec<String> {
    self.sites.keys().cloned().collect()
  }

  pub fn has_site(&self, name: &str) -> bool {
    self.sites.contains_key(&name.to_string())
  }

  pub fn get_site(&self, name: &str) -> Site {
    self.sites.get(&name.to_string()).unwrap().clone()
  }

  pub fn del_site(&mut self, name: &str) {
    self.sites.remove(&name.to_string());
  }

  pub fn update_site(&mut self, site: Site) {
    assert!(self.has_site(&site.name));
    self.add_site(site);
  }
}

