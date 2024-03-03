# implements eXtended Merkle Signature Scheme (XMSS)

from wots import WOTS
from shake import SHAKE
from math import ceil, floor, log
import hashlib
import time 

# initialize WOTS+ instance for XMSS
wots = WOTS(32, 16)
shake = SHAKE()
logging = True
timer = 20

def xprint(string):
    if logging: 
        print(string)

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
        mes = pkseed + adrs.adrs + m
        hash = shake.shake(mes, 8 * self.n, 512)
        digest = hashlib.shake_256(mes).digest(8 * self.n)
        return hash, digest

    def get_height(self, byte):
        """
        get the height of a tree (represented in bytes)
        :param byte: tree
        :return: height of the tree (bytes) in int
        """
        # tree height is the second word of address ADRS (4 bytes)
        return len(byte)

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

        for i in range(pow(2, z)):
            adrs.set_type(0)  # 0 is for WOTS+ hash address
            adrs.set_keypair_addr(s + i)
            node = wots.wots_PKgen(skseed, pkseed, adrs)
            adrs.set_type(2)  # 2 is hash tree address
            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)

            # while top node on stack has the same height as the node
            while len(stack) > 0 and self.get_height(stack[-1]) == self.get_height(node):
                adrs.set_tree_index((int.from_bytes(adrs.get_tree_height(), 'big') - 1) // 2)
                node = self.H(pkseed, adrs, stack.pop() + node)[1]
                adrs.set_tree_height(int.from_bytes(adrs.get_tree_height(), 'big') + 1)
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
        xprint("Begin XMSS signing. ")
        if not isinstance(idx, int):
            idx_int = int.from_bytes(idx, 'big')
        else:
            idx_int = idx
        auth = b''
        # build authentication path
        start = time.time() 
        for i in range(self.h):
            k = floor(idx_int / pow(2, i)) ^ 1
            auth += self.treehash(skseed, k * pow(2, i), i, pkseed, adrs)
            if time.time() - start > timer: 
                break

        adrs.set_type(0)
        adrs.set_keypair_addr(idx)
        sig = wots.wots_sign(m, skseed, pkseed, adrs)
        sig_xmss = sig + auth
        xprint("XMSS signature generated")
        return sig_xmss

    def get_sigs(self, sig):
        """
        extract the signatures from the XMSS signature
        :param sig: XMSS signature
        :return: list of signatures
        """
        sigs = []
        for i in range(self.h):
            sigs.append(sig[i * 2 * self.n: (2 * i + 1) * self.n])
        return sigs

    def get_auth(self, sig):
        """
        extract the auth paths from the XMSS signature
        :param sig: XMSS signature
        :return: list of auth paths
        """
        auths = []
        for i in range(self.h):
            auths.append(sig[(i + 1) * self.n:(i + 1) * (self.n * 2)])
        return auths

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
        xprint("Begin XMSS verification. ")
        # TODO: check this function
        node = []
        # compute WOTS+ pk from sig
        adrs.set_type(0)
        adrs.set_keypair_addr(idx)
        sigs = self.get_sigs(sig)  # extract signatures only from sig_xmss
        auths = self.get_auth(sig)  # extract the auth paths only from sig_xmss
        if isinstance(idx, int):
            idx_int = idx
        else:
            idx_int = int.from_bytes(idx, 'big')
        node.append(wots.wots_pkFromSig(sig, m, pkseed, adrs))

        # compute root from WOTS+ pk and auth path
        adrs.set_type(2)
        adrs.set_tree_index(idx)

        for i in range(self.h):
            adrs.set_tree_height(i+1)
            if floor(idx_int / pow(2, i)) % 2 == 0:
                adrs.set_tree_index(int.from_bytes(adrs.get_tree_index(), 'big') // 2)
                new_m = node[0] + auths[i]
            else:
                adrs.set_tree_index((int.from_bytes(adrs.get_tree_index(), 'big')- 1) // 2)
                new_m = auths[i] + node[0]
            new_node = self.H(pkseed, adrs, new_m)
            node[0] = new_node[1]
        xprint("XMSS verification is done.")
        return node[0]
