from mpyc.runtime import mpc
import argparse
from hashlib import sha3_224, sha3_256, sha3_512, shake_128, shake_256
from mpyc.gfpx import GFpX
import numpy as np

triangular_numbers = tuple(i*(o+1)//2 % 64 for i in range(1, 25))

round_constants = tuple(tuple(int(GFpX(2).powmod('x', 7*i + j, 'x⁸+x⁶+x⁵+x⁴+1')) % 2
                              for j in range(7))
                        for i in range(24))

secfld = mpc.SecFld(2)

def _keccak_f1600(s):
    """
    Keccak-f(1600) permutation applied to 1600-bit array s
    operating over secure GF(2) arrays
    """
    # convert s into 3D array a[x,y,z] = s[64(sy + x) + z]

    a = s.reshape(5, 5, 64).transpose(1, 0, 2)

    for r in range(24):
        # apply 0
        c = a.sum(axis=1)
        d = np.roll(c, 1, axis=0) + np.roll(np.roll(c, -1, axis=0), 1, axis=1)
        a += d[:, np.newaxis, :]

