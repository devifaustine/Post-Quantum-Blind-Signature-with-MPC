# implement FORS in SPHINCS+

from sphincs_params import *

class FORS:
    def __init__(self, n, k, t):
        self.n = n # security parameter - length of pk, sk. sig in bytes
        self.k = k # number of sk sets, trees and indices computed from input string
        self.t = t # number of elements per sk set, leaves per hash tree and upper bound on index values

    def fors_SKgen(self, skseed, adrs, idx):
        """
        generate a secret key for a given index
        :param skseed: SK.seed of SPHINCS+
        :param adrs: address
        :param idx: sk index = i*t+j
        :return: secret key of FORS
        """
        skADRS = adrs.copy() # copy addresst o create key gen address
        skADRS.setType(FORS_PRF)
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress())