
// storage and cli operations
extern crate rustc_serialize;
use self::rustc_serialize::json::{Json, encode};
use self::rustc_serialize::json;

use std::path::PathBuf;
use std::fs::File;
use std::env;
use std::fs::rename;
use std::fs::metadata;
use std::io::Write;
use std::io::Read;

use super::util::{memset};
use super::db::{Database, Site};
use super::crypto::{Secrets, decrypt_json};

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

pub fn init() {
  if has_storage_file() {
    panic!("Database file (~/.powdb) already exists.  Please delete it to 'init'.");
  }

  let mut sec = Secrets::fresh();
  get_new_password(&mut sec).unwrap();

  let db = Database::empty();
  put_storage(&db, &sec);
  println!("Empty database created.");
}

pub fn passwd() {
  println!("passwd nyi");
}

pub fn ls() {
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

pub fn add(name: &str, kind: &str) {
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

pub fn gen(name: &str, kind: &str) {
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

pub fn echo(name: &str, kind: &str) {
  let json = read_storage().unwrap();
  let (database, secrets) = load_database(&json, "to get secret");
  let site = database.get_site(name);
  let pwd = site.get_password(kind, &secrets).unwrap();
  println!("{}", pwd);
}

pub fn rm(name: &str, kind: &str) {
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

