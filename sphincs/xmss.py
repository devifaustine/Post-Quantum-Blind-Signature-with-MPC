# implements eXtended Merkle Signature Scheme (XMSS)

from wots import WOTS

# initialize WOTS+ instance for XMSS
wots = WOTS(32, 16)

class XMSS:
    def __init__(self, h, n, w):
        self.h = h  # height (number of levels - 1) of the tree
        self.n = n  # length in bytes of messages & each node
        self.w = w  # winternitz parameter

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

        for i in range(2^z):
            adrs.set_type(0)  # 0 is for WOTS+ hash address
            adrs.set_keypair_addr(s + i)
            node = wots.wots_PKgen(skseed, pkseed, adrs)

        # TODO: implement this function
        raise NotImplementedError("Not yet implemented")
