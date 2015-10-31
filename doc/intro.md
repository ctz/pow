## Terminology

* *master password*: a password needed to decrypt the password manager database.
* *site password*: password stored by the password manager.
* `||`: concatenation of byte strings.

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
### Text encodings
All structures are encoded with JSON.  All text of a JSON encoding is itself encoded
with UTF8 (recall that JSON is defined in terms of unicode codepoints, and therefore
isn't something that can be sent over the network or written to a file
outwith some text encoding).

### Password based encryption

Our PBE is built from the following pieces:

- The `PBKDF2-HMAC-SHA256` password key derivation function.
- The ChaCha20 stream cipher with 32-byte keys and 8-byte nonces.
- The `HMAC-SHA256` MAC with 32-byte keys.
- The `HKDF-Expand-SHA256` KDF with 32-byte input and 64-byte output.

The iteration count for PBKDF2 is described alongside each usage of this PBE.

#### Password key derivation

Inputs:

- `password`
- `salt`

Outputs:

- `Kmaster` master key

1. Apply `PBKDF2-HMAC-SHA256` to the input `password` and `salt` to produce a 32-byte intermediate key `Kmaster`.

### Per-encryption key derivation

Inputs:

- `Kmaster`
- `domain` usage seperation string

Outputs:

- `Ke` encryption key
- `Ks` signing key

1. Use `HKDF-Expand-SHA256` with inputs of the master key `Kmaster` and the given `domain`
   separation string, obtaining a 64-byte output.
2. Let `Ke` be the first 32 bytes, and `Ks` be the 32-byte remainder of the HKDF output.

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

1. Verify `tag` against `nonce || ciphertext` using `Ks`, in constant time.
   If this verification fails, yield an error and stop.
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

### Parameter choice
Passwords are padded to 64-byte boundaries.

Databases are padded to 2048-byte boundaries.

2<sup>22</sup> PBKDF2 iterations are used when saving for storage in the cloud.
2<sup>18</sup> PBKDF2 iterations are used when saving locally.

### Database structure and operations
#### Encryption
We encrypt JSON values with the following operations:

1. unicode-codepoints <- `JSON-encode`(value)
2. json-bytes <- `UTF8-encode`(unicode-codepoints)
3. bytes <- `pad`(json-bytes)
4. ciphertext <- `encrypt`(bytes)

#### Ciphertexts
Ciphertexts are stored as JSON objects with precisely the following keys:

- `cipher`: base64-encoded ciphertext.
- `nonce`: base64-encoded nonce.
- `tag`: base64-encoded HMAC tag.

#### Sites
JSON objects with the following mandatory elements:

- `ciphers` is a map from names to `ciphertext` encodings.  Names are (for example) 'password', 'secret question answer'; at the choice of the user.  These ciphertexts result from encrypting the JSON strings of the secret in question.
- `name` is a user-chosen string naming the site in question (like 'Google').
- `created` is a UNIX timestamp (i.e. non-leap seconds since 1970, measured in UTC) encoded as an integer for when this entry was first created.
- `updated` is another UNIX timestamp for when this entry was last updated.

Additionally, and optionally, `url` and `comment` are strings describing the site.  Any other items are allowed also.

#### KDF inputs
A JSON structure with plaintext inputs to the KDF in use.

- `kdf` is the name of the KDF in use.  `"pbkdf2-hmac-sha256"` is the only supported value; this is an extension point for future KDFs.
- `salt` is the base64-encoded random salt.
- `iter` is the iteration counter for PBKDF2.

#### Database
At the outermost level, a database is a JSON object with:

- `kdf`: a KDF inputs encoding.
- `cipher`: an encryption of the plaintext database encoding.

The database encoding is:

- `version`: an integer which should increase each time an update is made.
- `sites`: a mapping of site names to site encodings.

Other items are allowed and also encrypted; they must be maintained across edits.
