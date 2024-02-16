# Implements the WOTS+ class

from math import log, ceil, floor
from shake import SHAKE
from sphincs_params import *

shake = SHAKE()

class WOTS:
    def __init__(self, n = 32, w = 16):
        self.w = w # winternitz parameter - element of set {4, 16, 256}
        self.n = n # sec. param - message length and length of secret key, pubkey or signature element in bytes
        self.l1 = ceil(8 * n // log(w, 2))
        self.l2 = floor(log(self.l1 * (w - 1), 2) / log(w, 2)) + 1
        self.l = self.l1 + self.l2

    def chain(self, x, i, s, pkseed, adrs):
        """
        computes an iteration of F on an n-byte input using a WOTS+ hash address adrs and pubseed pk.seed
        :param x: input string
        :param i: start index
        :param s: number of steps
        :param pkseed: public seed PK.seed
        :param adrs: hash address adrs
        :return:
        """
        if (s == 0):
            return x
        if ((i + s) > (self.w - 1)):
            return None
        tmp = self.chain(x, i, s - 1, pkseed, adrs)
        adrs.set_hash_addr(i + s - 1)
        tmp = self.F(pkseed, adrs, tmp)
        return tmp

    def F(self, skseed, adrs, x):
        """
        computes shake256(sk.seed || adrs || x)
        :param skseed:
        :param adrs:
        :param x:
        :return:
        """
        # TODO: mes has to be adjusted accordingly as it is of type SecObj
        mes = skseed + adrs + x
        res = shake.shake(mes, 8 * self.n, 512)
        return res

    def wots_SKgen(self, skseed, adrs):
        """
        generates a WOTS+ secret key
        :param skseed: secret seed SK.seed
        :param adrs: address ADRS
        :return: secret key sk of WOTS+
        """
        # TODO: fix copy deep / shallow and adjust accordingly
        skAdrs = adrs.copy()
        skAdrs.set_type(WOTS_PRF)