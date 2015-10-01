import os
import json
import unicodedata
from hashlib import pbkdf2_hmac, sha256
import hmac
import base64
import datetime
import chacha

SALT_LENGTH = 16
PBKDF2_ITERATIONS = 2 ** 18

def canon(s):
    """
    Canonicalises the string s in NFC,
    then returns its UTF8 encoding in bytes.
    """
    s = unicodedata.normalize('NFC', s)
    return s.encode('utf8')

def b64_encode(b):
    return base64.b64encode(b).decode('utf8')

def b64_decode(s):
    return base64.b64decode(s.encode('utf8'))

def now():
    return datetime.datetime.now().isoformat()

# Crypto
class secrets:
    @staticmethod
    def fresh():
        s = secrets()
        s.salt = os.urandom(SALT_LENGTH)
        s.iterations = PBKDF2_ITERATIONS
        return s

    @staticmethod
    def decode(enc):
        s = secrets()
        s.salt = b64_decode(enc['salt'])
        s.iterations = enc['iter']
        return s

    def derive_keys(self, password_bytes):
        master = pbkdf2_hmac('sha256', password_bytes, self.salt, self.iterations)
        self.ke = hmac.new(master, b'encrypt\0', sha256).digest()
        self.ks = hmac.new(master, b'sign\0', sha256).digest()
        return self

    def encode(self):
        return dict(salt = b64_encode(self.salt), iter = self.iterations)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

class crypto:
    @staticmethod
    def pad(plain, boundary):
        npad = boundary - (len(plain) + 1) % boundary
        plain = plain + b'\x80' + (b'\x00' * npad)
        return plain

    @staticmethod
    def unpad(plain):
        npad = 0
        i = len(plain) - 1
        while plain[i] == 0x00:
            i -= 1
        assert plain[i] == 0x80
        return plain[:i]

    padding_password = lambda pt: crypto.pad(pt, 64)
    padding_database = lambda pt: crypto.pad(pt, 2048)

    @staticmethod
    def encrypt_json(js, sec, padding):
        """
        Encrypt the json-encodable object js using the secrets
        stored in the sec secrets object.

        This returns a dict with items for the things you need
        to decrypt.
        """
        nonce = os.urandom(8)
        plain = json.dumps(js).encode('utf8')
        plain = padding(plain)
        cipher = chacha.chacha20_cipher(sec.ke, nonce, plain)
        tag = hmac.new(sec.ks, nonce + cipher, sha256).digest()
        return dict(
                tag = b64_encode(tag),
                cipher = b64_encode(cipher),
                nonce = b64_encode(nonce)
                )

    @staticmethod
    def decrypt_json(enc, sec):
        """
        Takes the object returned by encrypt_json earlier, and returns
        the original input object using the keys in the sec secrets object.
        """
        nonce, cipher, tag = map(b64_decode, [enc['nonce'], enc['cipher'], enc['tag']])
        ourtag = hmac.new(sec.ks, nonce + cipher, sha256).digest()

        if len(nonce) != 8 or not hmac.compare_digest(ourtag, tag):
            raise IOError('corrupt ciphertext')

        plain = chacha.chacha20_cipher(sec.ke, nonce, cipher)
        plain = crypto.unpad(plain)
        return json.loads(plain.decode('utf8'))

# Model
class database:
    def __init__(self):
        self.sites = {}
        self.log = []
        self.loaded_version = 0

    @staticmethod
    def decrypt(enc, raw_password):
        sec = secrets.decode(enc['sec'])
        sec.derive_keys(canon(raw_password))

        plain = crypto.decrypt_json(enc['cipher'], sec)
        
        db = database()
        db.loaded_version = plain['version']
        db.log = plain['log']
        db.sites = dict((k, site.decode(v)) for k, v in plain['sites'].items())
        return sec, db

    def add_site(self, site):
        if site.name in self.sites:
            raise ValueError('site named %r already exists' % name)

        site.was_updated()
        self.sites[site.name] = site
        self.log.append(['add', site.name])

    def update_site(self, site):
        assert site.name in self.sites
        site.was_updated()
        self.sites[site.name] = site
        self.log.append(['update', site.name])

    def del_site(self, name):
        if name not in self.sites:
            return
        del self.sites[name]
        self.log.append(['del', name])

    def get_site(self, name):
        return self.sites[name]

    def encrypt(self, sec):
        """
        Encode and encrypt whole database, including metadata needed
        to decrypt it.
        """
        data = dict(
                sites = dict((k, v.encode()) for k, v in self.sites.items()),
                log = self.log,
                version = self.loaded_version + 1
                )
        
        cipher = crypto.encrypt_json(data, sec, crypto.padding_database)

        return dict(
                cipher = cipher,
                sec = sec.encode()
                )

class site:
    def __init__(self):
        self.ciphers = {}
        self.name = None
        self.url = None
        self.comment = None
        self.created = None
        self.updated = None

    @staticmethod
    def fresh(name):
        s = site()
        s.name = name
        s.created = now()
        return s

    @staticmethod
    def decode(enc):
        s = site()
        s.ciphers = enc['ciphers']
        s.name = enc['name']
        s.url = enc['url']
        s.comment = enc['comment']
        s.created = enc['created']
        s.updated = enc['updated']
        return s

    def set_password(self, kind, raw_password, sec):
        plain = b64_encode(canon(raw_password))
        cipher = crypto.encrypt_json(plain, sec, crypto.padding_password)
        self.ciphers[kind] = cipher

    def get_password(self, kind, sec):
        cipher = self.ciphers[kind]
        plain = crypto.decrypt_json(cipher, sec)
        return b64_decode(plain).decode('utf8')

    def was_updated(self):
        self.updated = now()

    def encode(self):
        return dict(
                ciphers = self.ciphers,
                name = self.name,
                url = self.url,
                comment = self.comment,
                created = self.created,
                updated = self.updated
                )

if __name__ == '__main__':
    testpw = 'password'

    sec = secrets.fresh()
    sec.derive_keys(canon(testpw))

    print(sec.encode())
    assert sec == sec
    assert secrets.decode(sec.encode()).derive_keys(canon(testpw)) == sec

    butt = dict(abc = 123)
    enc = crypto.encrypt_json(butt, sec, crypto.padding_password)
    print(enc)
    print(crypto.decrypt_json(enc, sec))

    s = site.fresh('google')
    s.set_password('password', 'dumbpassword', sec)
    print(json.dumps(s.encode()))

    db = database()
    db.add_site(s)

    store = db.encrypt(sec)

    print(db.encrypt(sec))

    sec2, db2 = database.decrypt(store, testpw)
    assert sec2 == sec
    print(db2.__dict__)

    print(db2.get_site(s.name).get_password('password', sec2))

    db2.update_site(s)
    db2.del_site(s.name)
