## Terminology

* *master password*: a password needed to decrypt the password manager database.
* *site password*: password stored by the password manager.
* *||*: concatenation of byte strings.

## Security model

pow is designed to be secure in the models described by
[Gasti and Rasmussen](http://www.cs.ox.ac.uk/files/6487/pwvault.pdf).

Specifically, we aim to ensure that our adversary cannot:

* learn passwords, site names, or meta-data stored in the database.
* alter the database to delete, insert or alter a site's information.

The adversary can:

* read and record all versions of the encrypted database.
* learn the total length of the database file(s).
* rewind the database to a previous copy of the database.
* observe times of alterations to the database and correlate these with external sources.
* corrupt the database such that it is unreadable, and therefore deny service.

## System requirements

pow must:

* *work across multiple devices*: Android devices, Linux and OS-X console, Windows desktop, and a modern web browser.
* *support syncing with web-connected storage* with extra protection against the risks introduced by this storage.
* *work offline*.
* *correctly track changes made over multiple devices* when syncing.
* *use modern cryptography*.
* *not expose passwords to the server when used from a web browser*. (note: this does not address the fundamental problem of serving trustworthy javascript to a web browser from an untrusted server.  It is more a case of hygiene and server complexity.)

## Design
### Encodings
All structures are encoded with JSON.  All text of a JSON encoding is itself encoded
with UTF8 (recall that JSON is defined in terms of unicode codepoints, and therefore
isn't something that can be sent over the network outwith some text encoding).

Passwords and other strings are stored normalised to NFC.

### Password based encryption

Our PBE is built from the following pieces:

- The `PBKDF2-HMAC-SHA256` password key derivation function.
- The ChaCha20 stream cipher with 32-byte keys and 8-byte nonces.
- The `HMAC-SHA256` MAC.

The iteration count for PBKDF2 is described alongside each usage of this PBE.

#### Key derivation

Inputs:

- `password`
- `salt`

Outputs:

- `Ke`
- `Ks`

1. Apply `PBKDF2-HMAC-SHA256` to the input `password` and `salt` to produce a 32-byte intermediate key `K`.
2. Derive 32-byte encryption and signing keys `Ke` and `Ks`:
   use `K` as a `HMAC-SHA256` key and sign the messages `encrypt\0` (the bytes `656e637279707400`)
   and `sign\0` (the bytes `7369676e00`) respectively.

#### Encryption

Inputs:

- `plaintext`
- `Ke`
- `Ks`

Outputs:

- `ciphertext`
- `nonce`
- `tag`

1. Choose a random 8-byte `nonce`.
2. Use ChaCha20 with `Ke` and the chosen `nonce` to encrypt the `plaintext` to yield the `ciphertext`.
3. `HMAC-SHA256` sign `nonce || ciphertext` using the key `Ks`; this is the output `tag`.

#### Decryption
Inputs:

- `ciphertext`
- `nonce`
- `tag`
- `Ke`
- `Ks`

Output:

- `plaintext` or an error

1. Verify `tag` against `nonce || ciphertext` using `Ks`, in constant time.  If this verification fails, yield an error and stop.
2. Decrypt the `ciphertext` to yield the `plaintext`, using `Ke` and the `nonce`.

### Plaintext padding
Our adversary can see the length of our ciphertexts.  We wish to disguise the length
of the database, especially over additions, updates and deletions.

We choose a message length that plaintext inputs to the PBE are padded to a multiple of.
For example, if we choose 4096 bytes, then plaintexts are padded to 4096, 8192, 12288, ... bytes.
The padding is a single `0x80` byte followed by zero or more `0x00` bytes to make the plaintext
the right size.  This is the same as ISO7816-4 padding.

### Operational security
We want good operational security when performing a typical operation, like listing available sites.
We therefore encrypt site passwords before storing them in the database; this is done with padding
to hide the exact password length.

The whole database is encrypted similarly to give the desired metadata security.

### Versioning
The server provides storage of `(version, database-ciphertext)` tuples.  `version`s are monotonically
increasing integers.  To accept a new `database-ciphertext`, the server requires the previous version
number; the update is rejected if the previous version number is not the latest.  In this case, the
client obtains the latest version from the server and replays the changes it made onto it, then sends
the result to the server.

This is designed to prevent updates to an old version obliterating newer versions.

