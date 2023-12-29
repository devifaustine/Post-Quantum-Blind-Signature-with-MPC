# Based on the public domain implementation in
# crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
# by D. J. Bernstein

def load_bigendian_32(x:bytearray):
    return x[3] | (x[2] << 8) | (x[1] << 16) | (x[0] << 24)

def load_bigendian_64(x):
    return x[7] | (x[6] << 8) | (x[5] << 16) | (x[4] << 24) | (x[3] << 32) | (x[2] << 40) | \
        (x[1] << 48) | (x[0] << 56)

def store_bigendian_32(x: bytearray, u):
    x[3] = u
    u >>= 8
    x[2] = u
    u >>= 8
    x[1] = u
    u >>= 8
    x[0] = u

def store_bigendian_64(x: bytearray, u):
    x[7] = u
    u >>= 8
    x[6] = u
    u >>= 8
    x[5] = u
    u >>= 8
    x[4] = u
    u >>= 8
    x[3] = u
    u >>= 8
    x[2] = u
    u >>= 8
    x[1] = u
    u >>= 8
    x[0] = u

def sha256_inc_finalize(out, state, in_, inlen):
    padded = bytearray(128)
    bytes = load_bigendian_64(state[32:40]) + inlen

    sha256_inc_blocks(state, in_, inlen)
    in_ += inlen
    inlen &= 63
    in_ -= inlen

    for i in range(inlen):
        padded[i] = in_[i]
    padded[inlen] = 0x80

    if inlen < 56:
        for i in range(inlen + 1, 56):
            padded[i] = 0
        padded[56] = (bytes >> 53) & 0xff
        padded[57] = (bytes >> 45) & 0xff
        padded[58] = (bytes >> 37) & 0xff
        padded[59] = (bytes >> 29) & 0xff
        padded[60] = (bytes >> 21) & 0xff
        padded[61] = (bytes >> 13) & 0xff
        padded[62] = (bytes >> 5) & 0xff
        padded[63] = (bytes << 3) & 0xff
        sha256_inc_blocks(state, padded, 64)
    else:
        for i in range(inlen + 1, 120):
            padded[i] = 0
        padded[120] = (bytes >> 53) & 0xff
        padded[121] = (bytes >> 45) & 0xff
        padded[122] = (bytes >> 37) & 0xff
        padded[123] = (bytes >> 29) & 0xff
        padded[124] = (bytes >> 21) & 0xff
        padded[125] = (bytes >> 13) & 0xff
        padded[126] = (bytes >> 5) & 0xff
        padded[127] = (bytes << 3) & 0xff
        sha256_inc_blocks(state, padded, 128)

    for i in range(32):
        out[i] = state[i]
    return out

def sha256_inc_blocks(state, in_, inblocks):
    bytes_ = load_bigendian_64(state[32:40])
    crypto_hashblocks_sha256(state, in_, 64 * inblocks)
    bytes_ += 64 * inblocks
    store_bigendian_64(state[32:40], bytes_)
    return state

def crypto_hashblocks_sha256(state, in_, inlen):
    # TODO: implement this function!
    return None
