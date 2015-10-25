
use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write;
use std::io::Read;

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
use crypto::hkdf::hkdf_expand;

extern crate fastpbkdf2;
use fastpbkdf2::pbkdf2_hmac_sha256;

const PBKDF2_TYPE: &'static str = "pbkdf2-hmac-sha256";
const PBKDF2_ITERATIONS: u32 = 1 << 20;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 8;

fn get_random(len: usize) -> Vec<u8> {
  OsRng::new().unwrap().gen_iter::<u8>().take(len).collect()
}

/* Copy [u8]s.  Yes, you need to provide this yourself.
 * copy_memory is unstable.  clone_from_slice is unstable.
 */
fn memcpy(target: &mut [u8], source: &[u8]) {
  assert!(target.len() == source.len());
  for (dst, src) in target.iter_mut().zip(source.iter()) {
    *dst = *src;
  }
}

/* Same goes for set_memory. */
fn memset(target: &mut [u8], val: u8) {
  for dst in target.iter_mut() {
    *dst = val;
  }
}

/* Temporary storage for encryption keys for a specific site. */
#[derive(Debug)]
struct Keys {
  kconf: [u8; 32],
  kauth: [u8; 32]
}

impl Drop for Keys {
  fn drop(&mut self) {
    memset(&mut self.kconf, 0u8);
    memset(&mut self.kauth, 0u8);
  }
}

/* Medium-term storage of KDF inputs plus resulting master key. */
#[derive(Debug,Clone)]
struct Secrets {
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
  fn derive_key(&mut self, password: &[u8]) -> &mut Secrets {
    pbkdf2_hmac_sha256(password,
                       &self.salt[..],
                       self.iterations,
                       &mut self.master);

    self.have_master = true;

    self
  }

  fn keys_for_db(&self) -> Keys {
    self.keys_for_site("")
  }

  fn keys_for_site(&self, site: &str) -> Keys {
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

  fn fresh() -> Secrets {
    Secrets {
      iterations: PBKDF2_ITERATIONS,
      salt: get_random(SALT_LENGTH),
      have_master: false,
      master: [0u8; 32]
    }
  }

  fn decode(encoding: &Json) -> Secrets {
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

fn encrypt_json(js: &Json, keys: &Keys, pad: Padding) -> Json {
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

fn decrypt_json(enc: &Json, keys: &Keys) -> Option<Json> {
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

fn utc_now() -> i64 {
  time::get_time().sec
}

const SITE_CIPHERS: &'static str = "ciphers";
const SITE_CREATED: &'static str = "created";
const SITE_UPDATED: &'static str = "updated";
const SITE_NAME: &'static str = "name";

#[derive(Debug,Clone)]
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
    let keys = sec.keys_for_site(&self.name);
    let cipher = encrypt_json(&password.to_string().to_json(),
                              &keys,
                              add_padding_password);
    self.ciphers.insert(kind.to_string(), cipher);
  }

  fn is_empty(&self) -> bool {
    self.ciphers.len() == 0
  }

  fn has_password(&self, kind: &str) -> bool {
    self.ciphers.contains_key(&kind.to_string())
  }

  fn del_password(&mut self, kind: &str) {
    self.ciphers.remove(&kind.to_string());
  }

  fn list_kinds(&self) -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    for k in self.ciphers.keys() {
      ret.push(k.clone());
    }
    ret
  }

  fn get_password(&self, kind: &str, sec: &Secrets) -> Option<String> {
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
struct Database {
  sites: BTreeMap<String, Site>,
  loaded_version: u32
}

impl Database {
  fn empty() -> Database {
    Database {
      sites: BTreeMap::new(),
      loaded_version: 0
    }
  }

  fn encrypt(&self, sec: &Secrets) -> Json {
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

  fn decode(json: &Json) -> Database {
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

  fn add_site(&mut self, site: Site) {
    self.sites.insert(site.name.clone(), site);
  }

  fn list_sites(&self) -> Vec<String> {
    self.sites.keys().cloned().collect()
  }

  fn has_site(&self, name: &str) -> bool {
    self.sites.contains_key(&name.to_string())
  }

  fn get_site(&self, name: &str) -> Site {
    self.sites.get(&name.to_string()).unwrap().clone()
  }

  fn del_site(&mut self, name: &str) {
    self.sites.remove(&name.to_string());
  }

  fn update_site(&mut self, site: Site) {
    assert!(self.has_site(&site.name));
    self.add_site(site);
  }
}

// storage and cli
extern crate docopt;
use docopt::Docopt;

use std::path::PathBuf;
use std::fs::File;
use std::env;
use std::fs::rename;
use std::fs::metadata;

struct PinEntry;
impl PinEntry {
  fn get_password(msg: &str) -> Option<String> {
    println!("get_password for {}", msg);
    Some("butt".to_string())
  }
}

fn _get_db_path(tmp: bool) -> PathBuf {
  let home = env::home_dir().expect("Cannot get home directory");
  let mut path = PathBuf::new();
  path.push(home);
  if tmp {
    path.push(".powdb.tmp");
  } else {
    path.push(".powdb");
  }
  path
}

fn get_tmp_path() -> PathBuf {
  _get_db_path(true)
}

fn get_db_path() -> PathBuf {
  _get_db_path(false)
}

fn has_storage_file() -> bool {
  metadata(get_db_path().as_path()).is_ok()
}

fn put_storage(db: &Database, sec: &Secrets) {
  {
    let mut f = File::create(get_tmp_path()).unwrap();
    
    let enc = db.encrypt(sec);
    let json = json::encode(&enc).unwrap();
    let bytes = json.as_bytes();
    f.write_all(bytes).unwrap();
  }

  rename(get_tmp_path(), get_db_path()).unwrap();
}

fn read_storage() -> Result<Json, &'static str> {
  {
    let mut f = File::open(get_db_path()).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    let json = Json::from_str(&s).unwrap();
    Ok(json)
  }
}

fn generate_password() -> String {
  return "asmdqwpewqkmepmepqwm".to_string();
}

fn get_new_password(sec: &mut Secrets) -> Result<(), &'static str> {
  let mut pw1 = PinEntry::get_password("Enter a new master password").unwrap();
  let mut pw2 = PinEntry::get_password("Confirm your new master password").unwrap();
  
  if pw1 != pw2 {
    return Err("Passwords differed");
  }

  // TODO: canonicalise unicode
  sec.derive_key(pw1.as_bytes());

  unsafe {
    memset(&mut pw1.as_mut_vec()[..], 0);
    memset(&mut pw2.as_mut_vec()[..], 0);
  }
  
  Ok(())
}

fn load_database(json: &Json, why: &str) -> (Database, Secrets) {
  let secjson = json.as_object().unwrap().get("kdf").unwrap();
  let mut secrets = Secrets::decode(secjson);

  let reason = format!("Enter your master password {}", why);
  let mut pw = PinEntry::get_password(&reason).unwrap();
  secrets.derive_key(pw.as_bytes());

  unsafe {
    memset(&mut pw.as_mut_vec()[..], 0);
  }

  let keys = secrets.keys_for_db();
  let dbjson = json.as_object().unwrap().get("cipher").unwrap();
  let plaintext = decrypt_json(&dbjson, &keys).unwrap();
  let db = Database::decode(&plaintext);
  
  (db, secrets)
}

struct Ops;
impl Ops {
  fn init() {
    if has_storage_file() {
      panic!("Database file (~/.powdb) already exists.  Please delete it to 'init'.");
    }

    let mut sec = Secrets::fresh();
    get_new_password(&mut sec).unwrap();

    let db = Database::empty();
    put_storage(&db, &sec);
    println!("Empty database created.");
  }

  fn passwd() {
    println!("passwd");
  }

  fn ls() {
    let json = read_storage().unwrap();
    let (database, _) = load_database(&json, "for listing");

    for name in database.list_sites() {
      println!("{}", name);

      let site = database.get_site(&name);
      for kind in site.list_kinds() {
        println!("  {}", kind);
      }
    }
  }

  fn add(name: &str, kind: &str) {
    let json = read_storage().unwrap();
    let (mut database, secrets) = load_database(&json, "to add new site");
    let mut pwd = PinEntry::get_password("").unwrap();

    if database.has_site(name) {
      let mut site = database.get_site(name);
      site.add_password(kind, &pwd, &secrets);
      database.update_site(site);
    } else {
      let mut site = Site::new(name);
      site.add_password(kind, &pwd, &secrets);
      database.add_site(site);
    }

    unsafe {
      memset(&mut pwd.as_mut_vec()[..], 0);
    }

    put_storage(&database, &secrets);
  }

  fn gen(name: &str, kind: &str) {
    let json = read_storage().unwrap();
    let (mut database, secrets) = load_database(&json, "to store new password");
    let mut pwd = generate_password();
    
    if database.has_site(name) {
      let mut site = database.get_site(name);
      site.add_password(kind, &pwd, &secrets);
      database.update_site(site);
    } else {
      let mut site = Site::new(name);
      site.add_password(kind, &pwd, &secrets);
      database.add_site(site);
    }
    
    unsafe {
      memset(&mut pwd.as_mut_vec()[..], 0);
    }

    put_storage(&database, &secrets);
  }

  fn echo(name: &str, kind: &str) {
    let json = read_storage().unwrap();
    let (database, secrets) = load_database(&json, "to get secret");
    let site = database.get_site(name);
    let pwd = site.get_password(kind, &secrets).unwrap();
    println!("{}", pwd);
  }

  fn rm(name: &str, kind: &str) {
    let reason = format!("to delete {} for {}", kind, name);
    let json = read_storage().unwrap();
    let (mut database, secrets) = load_database(&json, &reason);
    let mut site = database.get_site(name);

    if site.has_password(kind) {
      site.del_password(kind);
      println!("Deleted secret {} for site {}", kind, name);
    }

    if site.is_empty() {
      database.del_site(name);
      println!("Deleted site {} with no secrets", name);
    } else {
      database.update_site(site);
    }
    
    put_storage(&database, &secrets);
  }
}

static USAGE: &'static str = "
Usage:
  pow init
  pow passwd
  pow ls
  pow add <name> [<type>]
  pow gen <name> [<type>]
  pow echo <name> [<type>]
  pow rm <name> [<type>]
  pow paste <name> [<type>]
  pow pull
  pow push

Commands:
  pow init			create a new empty database
  pow passwd			change the password for an existing database
  pow ls			list all sites
  pow add <name> [<type>]	add secret for named site
  pow gen <name> [<type>]	generate a new secret for named site then echo it
  pow echo <name> [<type>]	echo secret for named site
  pow rm <name> [<type>]	delete secret for named site
  pow paste <name> [<type>]	put secret for named site on clipboard
  pow pull			download changes to database
  pow push			upload changes to database
";

#[derive(RustcDecodable,Debug)]
struct Args {
  cmd_init: bool,
  cmd_passwd: bool,
  cmd_ls: bool,
  cmd_add: bool,
  cmd_gen: bool,
  cmd_echo: bool,
  cmd_rm: bool,
  cmd_paste: bool,
  cmd_pull: bool,
  cmd_push: bool,
  arg_name: String,
  arg_type: String
}

fn main() {
  let mut args: Args = Docopt::new(USAGE)
    .and_then(|d| d.decode())
    .unwrap_or_else(|e| e.exit());
    
  if args.arg_type.is_empty() {
    args.arg_type = "password".to_string();
  }

  if args.cmd_init {
    Ops::init();
  } else if args.cmd_passwd {
    Ops::passwd();
  } else if args.cmd_ls {
    Ops::ls();
  } else if args.cmd_add {
    Ops::add(&args.arg_name, &args.arg_type);
  } else if args.cmd_gen {
    Ops::gen(&args.arg_name, &args.arg_type);
  } else if args.cmd_echo {
    Ops::echo(&args.arg_name, &args.arg_type);
  } else if args.cmd_rm {
    Ops::rm(&args.arg_name, &args.arg_type);
  } else {
    println!("unhandled op {:?} ", args);
  }
}
