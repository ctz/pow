"""
Pure python, slow implementation of chacha20.
"""

MOD32 = 1 << 32
MASK32 = 0xffffffff

TAU = b'expand 16-byte k'
SIGMA = b'expand 32-byte k'

def read32_le(b):
    return int.from_bytes(b, 'little')

def bytes32_le(i):
    return i.to_bytes(4, 'little')

def rotl32(x, n):
    return ((x << n) & MASK32) | (x >> (32 - n))

def chacha20_block(key0, key1, nonce, constant):
    """
    The chacha20 core function.  Takes 64 bytes of
    input, and returns 64 bytes of the result.
    The input is split into sections.
    """

    x0 = z0 = read32_le(constant[0:4])
    x1 = z1 = read32_le(constant[4:8])
    x2 = z2 = read32_le(constant[8:12])
    x3 = z3 = read32_le(constant[12:16])
    x4 = z4 = read32_le(key0[0:4])
    x5 = z5 = read32_le(key0[4:8])
    x6 = z6 = read32_le(key0[8:12])
    x7 = z7 = read32_le(key0[12:16])
    x8 = z8 = read32_le(key1[0:4])
    x9 = z9 = read32_le(key1[4:8])
    xa = za = read32_le(key1[8:12])
    xb = zb = read32_le(key1[12:16])
    xc = zc = read32_le(nonce[0:4])
    xd = zd = read32_le(nonce[4:8])
    xe = ze = read32_le(nonce[8:12])
    xf = zf = read32_le(nonce[12:16])
    
    for _ in range(10):
        z0 = (z0 + z4) % MOD32
        zc = rotl32(zc ^ z0, 16)
        z8 = (z8 + zc) % MOD32
        z4 = rotl32(z4 ^ z8, 12)
        z0 = (z0 + z4) % MOD32
        zc = rotl32(zc ^ z0, 8)
        z8 = (z8 + zc) % MOD32
        z4 = rotl32(z4 ^ z8, 7)
        
        z1 = (z1 + z5) % MOD32
        zd = rotl32(zd ^ z1, 16)
        z9 = (z9 + zd) % MOD32
        z5 = rotl32(z5 ^ z9, 12)
        z1 = (z1 + z5) % MOD32
        zd = rotl32(zd ^ z1, 8)
        z9 = (z9 + zd) % MOD32
        z5 = rotl32(z5 ^ z9, 7)
        
        z2 = (z2 + z6) % MOD32
        ze = rotl32(ze ^ z2, 16)
        za = (za + ze) % MOD32
        z6 = rotl32(z6 ^ za, 12)
        z2 = (z2 + z6) % MOD32
        ze = rotl32(ze ^ z2, 8)
        za = (za + ze) % MOD32
        z6 = rotl32(z6 ^ za, 7)
        
        z3 = (z3 + z7) % MOD32
        zf = rotl32(zf ^ z3, 16)
        zb = (zb + zf) % MOD32
        z7 = rotl32(z7 ^ zb, 12)
        z3 = (z3 + z7) % MOD32
        zf = rotl32(zf ^ z3, 8)
        zb = (zb + zf) % MOD32
        z7 = rotl32(z7 ^ zb, 7)
        
        z0 = (z0 + z5) % MOD32
        zf = rotl32(zf ^ z0, 16)
        za = (za + zf) % MOD32
        z5 = rotl32(z5 ^ za, 12)
        z0 = (z0 + z5) % MOD32
        zf = rotl32(zf ^ z0, 8)
        za = (za + zf) % MOD32
        z5 = rotl32(z5 ^ za, 7)
        
        z1 = (z1 + z6) % MOD32
        zc = rotl32(zc ^ z1, 16)
        zb = (zb + zc) % MOD32
        z6 = rotl32(z6 ^ zb, 12)
        z1 = (z1 + z6) % MOD32
        zc = rotl32(zc ^ z1, 8)
        zb = (zb + zc) % MOD32
        z6 = rotl32(z6 ^ zb, 7)
        
        z2 = (z2 + z7) % MOD32
        zd = rotl32(zd ^ z2, 16)
        z8 = (z8 + zd) % MOD32
        z7 = rotl32(z7 ^ z8, 12)
        z2 = (z2 + z7) % MOD32
        zd = rotl32(zd ^ z2, 8)
        z8 = (z8 + zd) % MOD32
        z7 = rotl32(z7 ^ z8, 7)
        
        z3 = (z3 + z4) % MOD32
        ze = rotl32(ze ^ z3, 16)
        z9 = (z9 + ze) % MOD32
        z4 = rotl32(z4 ^ z9, 12)
        z3 = (z3 + z4) % MOD32
        ze = rotl32(ze ^ z3, 8)
        z9 = (z9 + ze) % MOD32
        z4 = rotl32(z4 ^ z9, 7)

    x0 = (x0 + z0) % MOD32
    x1 = (x1 + z1) % MOD32
    x2 = (x2 + z2) % MOD32
    x3 = (x3 + z3) % MOD32
    x4 = (x4 + z4) % MOD32
    x5 = (x5 + z5) % MOD32
    x6 = (x6 + z6) % MOD32
    x7 = (x7 + z7) % MOD32
    x8 = (x8 + z8) % MOD32
    x9 = (x9 + z9) % MOD32
    xa = (xa + za) % MOD32
    xb = (xb + zb) % MOD32
    xc = (xc + zc) % MOD32
    xd = (xd + zd) % MOD32
    xe = (xe + ze) % MOD32
    xf = (xf + zf) % MOD32

    r = [bytes32_le(x) for x in (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf)]
    return b''.join(r)

def next_nonce(nonce):
    """
    Takes the full 16-byte nonce and increments the first 8 bytes as
    a little-endian counter.  Returns the next nonce.
    """
    l = list(nonce)
    i = 0
    while True:
        l[i] = (l[i] + 1) % 256
        if l[i] != 0:
            break
        i += 1
        if i == 8:
            break
    return bytes(l)

def chacha20_generate_keystream(key0, key1, nonce, constant, ll):
    """
    A generator which yields chacha20 keystream of ll bytes long.
    This is emitted in arbitrary sized blocks.
    """
    while ll:
        block = chacha20_block(key0, key1, nonce, constant)

        if ll < len(block):
            yield block[:ll]
            break

        yield block
        ll -= len(block)
        nonce = next_nonce(nonce)

def chacha20_keystream(key0, key1, nonce, constant, ll):
    """
    Returns ll bytes of chacha20 keystream.
    """
    return b''.join([ks for ks in chacha20_generate_keystream(key0, key1, nonce, constant, ll)])

def xor_bytes(a, b):
    """
    Returns the XOR of the bytes a and b.  The result is the
    length of a; this must be <= than the length of b.
    """
    return bytes([a[i] ^ b[i] for i in range(len(a))])

def chacha20_cipher(key, nonce, input):
    """
    Returns input encrypted/decrypted.  key can be 16 or 32 bytes.
    nonce must be 8 bytes; the counter is added to this and started at zero.
    """
    assert len(key) in (16, 32)
    assert len(nonce) == 8

    if len(key) == 16:
        constant = TAU
        key0 = key1 = key
    else:
        constant = SIGMA
        key0 = key[:16]
        key1 = key[16:]

    counter = bytes([0x00] * 8)

    result = []
    offs = 0
    for ks in chacha20_generate_keystream(key0, key1, counter + nonce, constant, len(input)):
        result.append(xor_bytes(ks, input[offs:]))
        offs += len(ks)

    return b''.join(result)

# Tests
import unittest

class TestChaCha20(unittest.TestCase):
    def test_block(self):
        # from section 7 of draft-agl-tls-chacha20poly1305-04
        zeroes = b'\0' * 16

        key0 = key1 = nonce = zeroes
        r = chacha20_block(key0, key1, nonce, SIGMA)
        self.assertEqual(r, bytes.fromhex('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'))

        key1 = zeroes[0:15] + bytes([0x01])
        r = chacha20_block(key0, key1, nonce, SIGMA)
        self.assertEqual(r, bytes.fromhex('4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963'))

        key1 = zeroes
        nonce = zeroes[0:15] + bytes([0x01])
        r = chacha20_block(key0, key1, nonce, SIGMA)
        self.assertEqual(r[:60], bytes.fromhex('de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'))

        nonce = zeroes[0:8] + bytes([0x01]) + zeroes[0:7]
        r = chacha20_block(key0, key1, nonce, SIGMA)
        self.assertEqual(r, bytes.fromhex('ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b'))

        nonce = bytes.fromhex('00000000000000000001020304050607')
        key0 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        key1 = bytes.fromhex('101112131415161718191a1b1c1d1e1f')
        r = chacha20_keystream(key0, key1, nonce, SIGMA, 256)
        self.assertEqual(r, bytes.fromhex('f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9'))

        # check using cipher api
        cipher = chacha20_cipher(key0 + key1, nonce[8:], bytes([0x00] * 256))
        assert cipher == r

        # check round trip
        msg = b'hello world'
        cipher = chacha20_cipher(key0 + key1, nonce[8:], msg)
        assert msg == chacha20_cipher(key0 + key1, nonce[8:], cipher)
        cipher = chacha20_cipher(key0, nonce[8:], msg)
        assert msg == chacha20_cipher(key0, nonce[8:], cipher)

if __name__ == '__main__':
    unittest.main()
