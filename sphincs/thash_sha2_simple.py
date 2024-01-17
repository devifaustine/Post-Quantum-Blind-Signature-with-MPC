from sphincs_params import *
from address import *
from utils import *

#TODO: define EXPAND_32

def ROTR_32(x, c):
    return (x >> c) | (x << (32 - c))

def ROTR_64(x, c):
    return (x >> c) | (x << (64 - c))

def Ch(x, y, z):
    return ((x & y) ^ (~x & z))

def Maj(x, y, z):
    return ((x & y) ^ (x & z) ^ (y & z))

def SHR(x, c):
    return (x >> c)

def Sigma0_32(x):
    return (ROTR_32(x, 2) ^ ROTR_32(x, 13) ^ ROTR_32(x, 22))

def Sigma1_32(x):
    return (ROTR_32(x, 6) ^ ROTR_32(x, 11) ^ ROTR_32(x, 25))

def sigma0_32(x):
    return (ROTR_32(x, 7) ^ ROTR_32(x, 18) ^ SHR(x, 3))

def sigma1_32(x):
    return (ROTR_32(x, 17) ^ ROTR_32(x, 19) ^ SHR(x, 10))

def M_32(w0, w14, w9, w1):
    w0 = Sigma1_32(w14) + w9 + Sigma0_32(w1) + w0
    return w0

def M_64(w0, w14, w9, w1):
    w0 = Sigma1_64(w14) + w9 + Sigma0_64(w1) + w0
    return w0

def Sigma0_64(x):
    return (ROTR_64(x, 28) ^ ROTR_64(x, 34) ^ ROTR_64(x, 39))

def Sigma1_64(x):
    return (ROTR_64(x, 14) ^ ROTR_64(x, 18) ^ ROTR_64(x, 41))

def sigma0_64(x):
    return (ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ SHR(x, 7))

def sigma1_64(x):
    return (ROTR_64(x, 19) ^ ROTR_64(x, 61) ^ SHR(x, 6))

def F_32(w, k):
    global a, b, c, d, e, f, g, h  # Assuming these variables are defined globally
    T1 = h + Sigma1_32(e) + Ch(e, f, g) + k + w
    T2 = Sigma0_32(a) + Maj(a, b, c)
    h, g, f, e, d, c, b, a = g, f, e, d + T1, c, b, a, T1 + T2

def load_bigendian_32(x):
    return x[3] | (x[2] << 8) | (x[1] << 16) | (x[0] << 24)

def load_bigendian_64(x):
    return x[7] | (x[6] << 8) | (x[5] << 16) | (x[4] << 24) | (x[3] << 32) | (x[2] << 40) | \
        (x[1] << 48) | (x[0] << 56)

def store_bigendian_32(x:bytearray, u):
    x[3] = u
    u >>= 8
    x[2] = u
    u >>= 8
    x[1] = u
    u >>= 8
    x[0] = u
    return x

def store_bigendian_64(x:bytearray, u):
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
    return x

# takes an array of inblocks concatenated arrays of SPX_N bytes
def thash(out, in_, inblocks, ctx, addr):
    outbuf = bytearray(SPX_SHA256_OUTPUT_BYTES)
    sha2_state = bytearray(40)
    buf = bytearray(SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)

    # Retrieve precomputed state containing pub_seed
    sha2_state = ctx.state_seeded

    buf[0:SPX_SHA256_ADDR_BYTES] = addr
    buf[SPX_SHA256_ADDR_BYTES:SPX_SHA256_ADDR_BYTES + inblocks*SPX_N] = in_

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N)
    out[0:SPX_N] = outbuf
    return out

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

def sha256_inc_blocks(state:bytearray, in_, inblocks):
    bytes = load_bigendian_64(state[32:40])

    crypto_hashblocks_sha256(state, in_, 64 * inblocks)
    bytes += 64 * inblocks

    store_bigendian_64(state[32:40], bytes)
    return state


def crypto_hashblocks_sha256(statebytes:bytearray, in_, inlen):
    state = bytearray(32)
    a = load_bigendian_32(statebytes + 0)
    state[0] = a
    b = load_bigendian_32(statebytes + 4)
    state[1] = b
    c = load_bigendian_32(statebytes + 8)
    state[2] = c
    d = load_bigendian_32(statebytes + 12)
    state[3] = d
    e = load_bigendian_32(statebytes + 16)
    state[4] = e
    f = load_bigendian_32(statebytes + 20)
    state[5] = f
    g = load_bigendian_32(statebytes + 24)
    state[6] = g
    h = load_bigendian_32(statebytes + 28)
    state[7] = h

    while(inlen >= 64):
        w0 = load_bigendian_32(in_ + 0)
        w1 = load_bigendian_32(in_ + 4)
        w2 = load_bigendian_32(in_ + 8)
        w3 = load_bigendian_32(in_ + 12)
        w4 = load_bigendian_32(in_ + 16)
        w5 = load_bigendian_32(in_ + 20)
        w6 = load_bigendian_32(in_ + 24)
        w7 = load_bigendian_32(in_ + 28)
        w8 = load_bigendian_32(in_ + 32)
        w9 = load_bigendian_32(in_ + 36)
        w10 = load_bigendian_32(in_ + 40)
        w11 = load_bigendian_32(in_ + 44)
        w12 = load_bigendian_32(in_ + 48)
        w13 = load_bigendian_32(in_ + 52)
        w14 = load_bigendian_32(in_ + 56)
        w15 = load_bigendian_32(in_ + 60)

        F_32(w0, 0x428a2f98)
        F_32(w1, 0x71374491)
        F_32(w2, 0xb5c0fbcf)
        F_32(w3, 0xe9b5dba5)
        F_32(w4, 0x3956c25b)
        F_32(w5, 0x59f111f1)
        F_32(w6, 0x923f82a4)
        F_32(w7, 0xab1c5ed5)
        F_32(w8, 0xd807aa98)
        F_32(w9, 0x12835b01)
        F_32(w10, 0x243185be)
        F_32(w11, 0x550c7dc3)
        F_32(w12, 0x72be5d74)
        F_32(w13, 0x80deb1fe)
        F_32(w14, 0x9bdc06a7)
        F_32(w15, 0xc19bf174)

        EXPAND_32

        F_32(w0, 0xe49b69c1)
        F_32(w1, 0xefbe4786)
        F_32(w2, 0x0fc19dc6)
        F_32(w3, 0x240ca1cc)
        F_32(w4, 0x2de92c6f)
        F_32(w5, 0x4a7484aa)
        F_32(w6, 0x5cb0a9dc)
        F_32(w7, 0x76f988da)
        F_32(w8, 0x983e5152)
        F_32(w9, 0xa831c66d)
        F_32(w10, 0xb00327c8)
        F_32(w11, 0xbf597fc7)
        F_32(w12, 0xc6e00bf3)
        F_32(w13, 0xd5a79147)
        F_32(w14, 0x06ca6351)
        F_32(w15, 0x14292967)

        EXPAND_32

        F_32(w0, 0x27b70a85)
        F_32(w1, 0x2e1b2138)
        F_32(w2, 0x4d2c6dfc)
        F_32(w3, 0x53380d13)
        F_32(w4, 0x650a7354)
        F_32(w5, 0x766a0abb)
        F_32(w6, 0x81c2c92e)
        F_32(w7, 0x92722c85)
        F_32(w8, 0xa2bfe8a1)
        F_32(w9, 0xa81a664b)
        F_32(w10, 0xc24b8b70)
        F_32(w11, 0xc76c51a3)
        F_32(w12, 0xd192e819)
        F_32(w13, 0xd6990624)
        F_32(w14, 0xf40e3585)
        F_32(w15, 0x106aa070)

        EXPAND_32

        F_32(w0, 0x19a4c116)
        F_32(w1, 0x1e376c08)
        F_32(w2, 0x2748774c)
        F_32(w3, 0x34b0bcb5)
        F_32(w4, 0x391c0cb3)
        F_32(w5, 0x4ed8aa4a)
        F_32(w6, 0x5b9cca4f)
        F_32(w7, 0x682e6ff3)
        F_32(w8, 0x748f82ee)
        F_32(w9, 0x78a5636f)
        F_32(w10, 0x84c87814)
        F_32(w11, 0x8cc70208)
        F_32(w12, 0x90befffa)
        F_32(w13, 0xa4506ceb)
        F_32(w14, 0xbef9a3f7)
        F_32(w15, 0xc67178f2)

        a += state[0]
        b += state[1]
        c += state[2]
        d += state[3]
        e += state[4]
        f += state[5]
        g += state[6]
        h += state[7]

        state[0] = a
        state[1] = b
        state[2] = c
        state[3] = d
        state[4] = e
        state[5] = f
        state[6] = g
        state[7] = h

        in_ += 64
        inlen -= 64

    store_bigendian_32(statebytes + 0, state[0])
    store_bigendian_32(statebytes + 4, state[1])
    store_bigendian_32(statebytes + 8, state[2])
    store_bigendian_32(statebytes + 12, state[3])
    store_bigendian_32(statebytes + 16, state[4])
    store_bigendian_32(statebytes + 20, state[5])
    store_bigendian_32(statebytes + 24, state[6])
    store_bigendian_32(statebytes + 28, state[7])

    return inlen;