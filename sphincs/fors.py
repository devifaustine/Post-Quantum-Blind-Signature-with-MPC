# implement FORS in SPHINCS+

from sphincs_params import *
from address import ADRS
from shake import SHAKE
from math import log, floor

shake = SHAKE()
y = 0
address = ADRS(y.to_bytes(32, 'big'))

# Note F(pkseed, adrs, m1) = shake256(pkseed||adrs||m1, 8n)

class FORS:
    def __init__(self, n, k, t):
        self.a = log(t, 2)
        self.n = n # security parameter - length of pk, sk. sig in bytes
        self.k = k # number of sk sets, trees and indices computed from input string
        self.t = t # number of elements per sk set, leaves per hash tree and upper bound on index values

    def prf_addr(self, key, addr):
        """
        generate a pseudo-random function (PRF) from a key and an address
        :param key: key
        :param addr: address
        :return: PRF
        """
        # TODO: where does addr come in play? what is it used for? - check prf_addr in sphincsplus and compare
        res = shake.shake(key, self.n, 512)
        return res

    def fors_SKgen(self, skseed, adrs, idx):
        """
        generate a secret key for a given index
        :param skseed: SK.seed of SPHINCS+
        :param adrs: address ADRS
        :param idx: sk index = i*t+j
        :return: secret key of FORS
        """
        # TODO: find out if copy is deep or shallow copy
        skADRS = adrs.copy() # copy address to create key gen address
        skADRS.set_type(3) # 3 = FORS tree address, 4 = FORS tree roots compression address
        skADRS.set_keypair_addr(adrs.get_keypair_addr())

        skADRS.set_tree_height(0) # height of the tree
        skADRS.set_tree_index(idx)
        sk = self.prf_addr(skseed, skADRS) # generate sk using PRF

        return sk

    def F(self, pkseed, adrs, m1):
        """
        computes shake256(pkseed||adrs||m1, 8n)
        :param pkseed: public seed
        :param adrs: address ADRS
        :param m1:
        :return: the hash value
        """
        # TODO: find out how to combine all these values below to mes
        mes = pkseed + adrs + m1
        hash = shake.shake(mes, 8 * self.n, 512)
        return hash

    def H(self, pkseed, adrs, m):
        """
        computes shake256(pkseed||adrs||m, 8n)
        :param pkseed: public seed
        :param adrs: address ADRS
        :param m: m1 || m2
        :return: the hash value
        """
        mes = pkseed + adrs + m
        hash = shake.shake(mes, 8 * self.n, 512)
        return hash

    def fors_treehash(self, skseed, s, z, pkseed, adrs):
        """
        computes the root node of a FORS tree
        :param skseed: secret seed
        :param s: start index
        :param z: target node height
        :param pkseed: public seed
        :param adrs: address ADRS
        :return: n-byte root node - top node on stack
        """
        if (s % (1 << z)) != 0:
            return -1

        stack = []

        for i in range(pow(2, z)):
            idx = s + i
            sk = self.fors_SKgen(skseed, adrs, idx)
            node = self.F(pkseed, adrs, sk)
            adrs.set_tree_height(1)
            adrs.set_tree_index(idx)

            while stack and stack[-1].height == node.height:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                # TODO: stack.pop() || node - concatenation here (check the types and adjust)
                node = self.H(pkseed, adrs, (stack.pop() + node))
                adrs.set_tree_height(adrs.get_tree_height() + 1)

            stack.append(node)

        return stack.pop()

    def fors_PKgen(self, skseed, pkseed, adrs):
        """
        compute public key for FORS
        :param skseed: secret seed SPHINCS+
        :param pkseed: public seed SPHINCS+
        :param adrs: address
        :return: FORS public key PK
        """
        forspkAdrs = adrs.copy()

        root = []
        for i in range(self.k):
            root[i] = self.fors_treehash(skseed, i * self.t, self.a, pkseed, adrs)

        forspkAdrs.set_type(4)
        forspkAdrs.set_keypair_addr(adrs.get_keypair_addr())
        pk = self.F(pkseed, forspkAdrs, root)

        return pk

    def fors_sign(self, m, skseed, pkseed, adrs):
        """
        signing function for FORS
        :param m: bitstring to be signed
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: FORS signature SIG_FORS
        """
        sig_fors = b''

        # compute signature elements
        for i in range(self.k):
            # get next index
            idx_start = i * int(log(self.t, 2))
            idx_end = (i + 1) * int(log(self.t, 2))
            idx = int(m[idx_start:idx_end], 2)

            # pick private key element
            sk_element = self.fors_SKgen(skseed, adrs, i * self.t + idx)
            sig_fors += sk_element

            # compute auth path
            auth = b''
            for j in range(self.a):
                s = floor(idx / (2 ** j)) ^ 1
                auth += self.fors_treehash(skseed, i * self.t + s * (2 ** j), j, pkseed, adrs)

            sig_fors += auth

        return sig_fors

    def fors_pkFromSig(self, sig_fors, m, pkseed, adrs):
        """
        retrieve FORS public key from signature
        :param sig_fors: FORS signature
        :param m: k log t - bitstring
        :param pkseed: SPHINCS+ public seed
        :param adrs: address ADRS
        :return: PK seed of FORS
        """
        # TODO: implement this function!
        raise NotImplementedError("Not yet implemented")