# implements eXtended Merkle Signature Scheme (XMSS)

from wots import WOTS
from shake import SHAKE
from math import ceil, floor, log

# initialize WOTS+ instance for XMSS
wots = WOTS(32, 16)
shake = SHAKE()

#TODO: test and check this class and its functions 

class XMSS:
    def __init__(self, h, n, w):
        self.h = h  # height (number of levels - 1) of the tree
        self.n = n  # length in bytes of messages & each node
        self.w = w  # winternitz parameter

    def H(self, pkseed, adrs, m):
        """
        tweakable hash H
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :param m: message
        :return: SHAKE256(pkseed || adrs || m, 8n)
        """
        mes = pkseed + adrs + m
        return shake.shake(mes, 8 * self.n, 512)

    def treehash(self, skseed, s, z, pkseed, adrs):
        """
        computes the root of the tree
        :param skseed: SK.seed of SPHINCS+
        :param s: start index
        :param z: target node height
        :param pkseed: PK.seed of SPHINCS+
        :param adrs: address ADRS
        :return: n-byte root node
        """
        if (s % (1 << z)) != 0:
            raise ValueError("start index s must be a multiple of 2^z")

        stack = []

        for i in range(2^z):
            adrs.set_type(0)  # 0 is for WOTS+ hash address
            adrs.set_keypair_addr(s + i)
            node = wots.wots_PKgen(skseed, pkseed, adrs)
            adrs.set_type(2)  # 2 is hash tree address
            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)
            # while top node on stack has the same height as the node
            while len(stack) > 0 and stack[-1][1] == adrs.get_tree_height():
                adrs.set_tree_index((adrs.get_tree_index() - 1) / 2)
                node = self.H(pkseed, adrs, stack.pop() + node)
                adrs.set_tree_height(adrs.get_tree_height() + 1)
            stack.append(node)
        return stack.pop()

    def xmss_pkgen(self, skseed, pkseed, adrs):
        """
        generate XMSS public key
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :return: XMSS pubkey
        """
        pk = self.treehash(skseed, 0, self.h, pkseed, adrs)
        return pk

    def xmss_sign(self, m, skseed, idx, pkseed, adrs):
        """
        generate XMSS signature
        :param m: message to be signed (n-byte)
        :param skseed: SPHINCS+ secret seed
        :param idx: index
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :return: XMSS signature SIG_XMSS(sig || AUTH)
        """
        auth = b''
        # build authentication path
        for i in range(self.h):
            k = floor(idx / pow(2, i)) ^ 1
            auth += self.treehash(skseed, k * pow(2, i), i, pkseed, adrs)

        adrs.set_type(0)
        adrs.set_keypair_addr(idx)
        sig = wots.wots_sign(m, skseed, pkseed, adrs)
        sig_xmss = sig + auth
        return sig_xmss

    def xmss_pk_from_sig(self, idx, sig, m, pkseed, adrs):
        """
        generate XMSS public key from signature
        :param idx: index
        :param sig: XMSS signature
        :param m: n-byte message
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :return: n-byte root value node[0] / public key of XMSS
        """
        # TODO: check this function
        node = []
        # compute WOTS+ pk from sig
        adrs.set_type(0)
        adrs.set_keypair_addr(idx)
        sig = sig[:self.n]  # extract sig from sig_xmss
        auth = sig[self.n:]
        node[0] = wots.wots_pkFromSig(sig, m, pkseed, adrs)

        # compute root from WOTS+ pk and auth path
        adrs.set_type(2)
        adrs.set_tree_index(idx)
        for i in range(self.h):
            adrs.set_tree_height(i+1)
            if floor(idx / pow(2, i)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() / 2)
                node[1] = self.H(pkseed, adrs, node[0] + auth[i])
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) / 2)
                node[1] = self.H(pkseed, adrs, auth[i] + node[0])
            node[0] = node[1]
        return node[0]
