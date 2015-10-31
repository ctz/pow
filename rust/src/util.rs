
extern crate rand;
use self::rand::Rng;
use self::rand::os::OsRng;

/* Generate random material. */
pub fn get_random(len: usize) -> Vec<u8> {
  OsRng::new().unwrap().gen_iter::<u8>().take(len).collect()
}

/* Copy [u8]s.  Yes, you need to provide this yourself.
 * copy_memory is unstable.  clone_from_slice is unstable.
 */
pub fn memcpy(target: &mut [u8], source: &[u8]) {
  assert!(target.len() == source.len());
  for (dst, src) in target.iter_mut().zip(source.iter()) {
    *dst = *src;
  }
}

/* Same goes for set_memory. */
pub fn memset(target: &mut [u8], val: u8) {
  for dst in target.iter_mut() {
    *dst = val;
  }
}

