# Implements the WOTS+ class
import copy
from math import log, ceil, floor
from shake import SHAKE
import hashlib

logging = True
shake = SHAKE()

def xprint(string):
    if logging:
        print(string)

def base_w(x, w, out_len):
    """
    converts a bytestring to a base w numbers - integers in set {0, ..., w-1}
    :param x: integer
    :param w: winternitz parameter
    :param out_len: output length
    :return: out_len int array basew
    """
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
        #xprint("chain function started")
        if (s == 0):
            return x
        if ((i + s) > (self.w - 1)):
            return None
        tmp = self.chain(x, i, s - 1, pkseed, adrs)
        adrs.set_hash_addr(i + s - 1)
        tmp = self.F(pkseed, adrs, tmp)[1]
        #print("tmp: ", tmp)
        return tmp

    def F(self, skseed, adrs, x):
        """
        computes shake256(sk.seed || adrs || x)
        :param skseed:
        :param adrs:
        :param x:
        :return:
        """
        if isinstance(x, int):
            x = x.to_bytes(4, 'big')
        mes = skseed + adrs.adrs + x
        res = shake.shake(mes, 8 * self.n, 512)
        digest = hashlib.shake_256(mes).digest(8 * self.n)
        return res, digest

    def PRF(self, skseed, adrs):
        """
        pseudorandom function
        :param skseed:
        :param adrs:
        :return:
        """
        mes = skseed + adrs.adrs
        res = shake.shake(mes, 8 * self.n, 512)
        digest = hashlib.shake_256(mes).digest(8 * self.n)
        return res, digest

    def T_len(self, pkseed, adrs, m):
        """
        computes tweakable hash Tl = SHAKE256(pk.seed || adrs || m, 8n)
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :param m: message
        :return: hash value
        """
        mes = pkseed + adrs.adrs + m
        hash = shake.shake(mes, 8 * self.n, 512)
        digest = hashlib.shake_256(mes).digest(8 * self.n)
        return hash, digest

    def wots_PKgen(self, skseed, pkseed, adrs):
        """
        generate WOTS+ public key
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ public key
        """
        wotspkAdrs = copy.deepcopy(adrs)  # copy address to create OTS pubkey address
        skadrs = copy.deepcopy(adrs)  # copy address to create key gen address
        skadrs.set_type(1)  # 1 is for WOTS+ public key compression address (type + keypairadr + padding 0)
        skadrs.set_keypair_addr(adrs.get_keypair_addr())

        sk = b''
        tmp = b''

        for i in range(self.l):
            skadrs.set_chain_addr(i)
            skadrs.set_hash_addr(0)
            sk += self.PRF(skseed, skadrs)[1]
            adrs.set_chain_addr(i)
            adrs.set_hash_addr(0)
            tmp += self.chain(sk[i], 0, self.w -1, pkseed, adrs)

        wotspkAdrs.set_type(1)  # 1: WOTS PK
        wotspkAdrs.set_keypair_addr(adrs.get_keypair_addr())
        pk = self.T_len(pkseed, wotspkAdrs, tmp)[1]
        return pk

    def wots_skgen(self, skseed, adrs):
        """
        generates a WOTS+ secret key sk
        :param skseed: SPHINCS+ secret seed
        :param adrs: address
        :return: WOTS+ private key
        """
        skadrs = copy.deepcopy(adrs)  # copy address to create a keygen address
        skadrs.set_type(5)  # 5 is for WOTS+ PRF
        skadrs.set_keypair_addr(adrs.get_keypair_addr())
        sk = b''
        for i in range(self.l):
            skadrs.set_chain_addr(i)
            skadrs.set_hash_addr(0)
            sk += self.PRF(skseed, skadrs)[1]
        xprint("WOTS+ secret key generated.")
        return sk


    def wots_sign(self, m, skseed, pkseed, adrs):
        """
        creates WOTS+ signature
        :param m: message to be signed
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ signature sig
        """
        xprint("Begin WOTS signing. ")
        checksum = 0

        # convert message to base w
        msg = base_w(m, self.w, self.l1)

        # compute checksum
        for i in range(self.l1):
            checksum += self.w - 1 - msg[i]

        # convert checksum to base w
        if log(self.w, 2) % 8 != 0:
            checksum = checksum << (8 - int((log(self.w, 2) * self.l2) % 8))
        l2_bytes = ceil((self.l2 * log(self.w, 2)) / 8)
        tmp1 = base_w(checksum.to_bytes(l2_bytes, 'big'), self.w, self.l2)
        msg += tmp1

        skadrs = copy.deepcopy(adrs) # copy address to create keygen address
        skadrs.set_type(5)
        skadrs.set_keypair_addr(adrs.get_keypair_addr())

        sig = b''

        for i in range(self.l):
            skadrs.set_chain_addr(i)
            skadrs.set_hash_addr(0)
            sk = self.PRF(skseed, skadrs)[1]
            adrs.set_chain_addr(i)
            adrs.set_hash_addr(0)
            sig += self.chain(sk, 0, msg[i], pkseed, adrs)
        xprint("WOTS+ signature generated.")
        return sig

    def wots_pkFromSig(self, sig, m, pkseed, adrs):
        """
        derive WOTS+ public key from the signature
        :param sig: WOTS+ signature
        :param m: message
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: WOTS+ public key
        """
        xprint("Begin WOTS verification.")
        checksum = 0
        wotspkAdrs = copy.deepcopy(adrs)

        # convert message to base w
        msg = base_w(m, self.w, self.l1)

        # compute checksum
        for i in range(self.l1):
            checksum += self.w - 1 - msg[i]

        # convert checksum to base w
        checksum = checksum << (8 - int((log(self.w, 2) * self.l2) % 8))
        l2_bytes = ceil((self.l2 * log(self.w, 2)) / 8)
        tmp1 = base_w(checksum.to_bytes(l2_bytes, 'big'), self.w, self.l2)
        msg += tmp1
        tmp = b''
        for i in range(self.l):
            adrs.set_chain_addr(i)
            tmp += self.chain(sig[i*self.n:(i+1)*self.n], msg[i], self.w - 1 - msg[i], pkseed, adrs)

        wotspkAdrs.set_type(1)  # 1: WOTS PK
        wotspkAdrs.set_keypair_addr(adrs.get_keypair_addr())
        pk_sig = self.T_len(pkseed, wotspkAdrs, tmp)[1]
        xprint("WOTS+ verification done.")
        return pk_sig

