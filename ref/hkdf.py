import hmac
import hashlib

def expand(h, prk, info, L):
    out = b''

    t = b''
    i = 0

    while len(out) <= L:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t

    return out[:L]

if __name__ == '__main__':
    x = expand(hashlib.sha256,
               bytes.fromhex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
               bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),
               42)
    assert x == bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
