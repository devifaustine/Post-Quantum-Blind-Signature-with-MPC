# Implements the WOTS+ class

from math import log, ceil, floor
from shake import SHAKE
from sphincs_params import *

shake = SHAKE()

def base_w(x, w, out_len):
    """
    converts an integer to base w
    :param x: integer
    :param w: winternitz parameter
    :param out_len: output length
    :return: out_len int array basew
    """
    # TODO: check this function and implement it
    in_ = 0
    out_ = 0
    total = 0
    bits = 0
    basew = [0] * out_len

    for consumed in range(out_len):
        if bits == 0:
            total = x[in_]
            in_ += 1
            bits += 8
        bits -= int(log(w, 2))
        basew[out_] = (total >> bits) & (w - 1)
        out_ += 1
    return basew

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
        skAdrs.set_type(1)  # 1 is for WOTS+ public key compression address (type + keypairadr + padding 0)

        raise NotImplementedError("Not yet implemented")

    def wots_PKgen(self, skseed, pkseed, adrs):
        """
        generate WOTS+ public key
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ public key
        """
        # TODO: check copy() function deep/shallow
        wotspkAdrs = adrs.copy()  # copy address to create OTS pubkey address
        skadrs = adrs.copy()  # copy address to create key gen address
        skadrs.set_type(1)  # 1 is for WOTS+ public key compression address (type + keypairadr + padding 0)
        skadrs.set_keypair_addr(adrs.get_keypair_addr())

        # TODO: find out what len is

        # TODO: implement the function
        raise NotImplementedError("Not yet implemented")

    def wots_sign(self, m, skseed, pkseed, adrs):
        """
        creates WOTS+ signature
        :param m: message to be signed
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ signature sig
        """
        checksum = 0

        # convert message to base w
        msg = base_w(m, self.w, self.l1)

        # TODO: implement the function
        raise NotImplementedError("Not yet implemented")

    def wots_pkFromSig(self, sig, m, pkseed, adrs):
        """
        derive WOTS+ public key from the signature
        :param sig: WOTS+ signature
        :param m: message
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ public key
        """
        # TODO: implement the function
        raise NotImplementedError("Not yet implemented")

