from mpyc.runtime import mpc
from math import log, floor
import pyspx.shake_256f
import random
import string
import numpy as np
from shake import SHAKE
from sphincs_params import *
from address import ADRS
from utils import UTILS
from fors import FORS
from hypertree import Hypertree

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

# this can be set to 1 if you want the signature to be randomized (for security)
RANDOMIZE = 0
shake = SHAKE()
secfld = mpc.SecFld(2)
util = UTILS()

class SPHINCS(object):
    # TODO: make the variables accessible and changable from main() in mpyc_sphincs_benchmark.py
    def __init__(self, n=32, m=512, h=68, d=17, w=16, tau=16, k=35):
        """Initializes SPHINCS+-256f according to docs

        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- number of layers in the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        tau -- layers in the HORST tree (2^tau is no. of secret-key elements)
        k -- number of trees in FORS
        #TODO: add t to the constructor argument and fix the code
        t -- number of leaves of FORS tree

        resulting signature would be 49856 bytes long
        """
        self.n = n  # security parameter in bytes
        self.m = m
        self.h = h
        self.d = d
        self.w = w
        self.tau = tau
        self.t = 1 << tau
        self.k = k
        self.a = log(self.t)
        SPX_N = 32
        SPX_FULL_HEIGHT = 68
        SPX_FORS_HEIGHT = 9
        SPX_FORS_TREES = 35
        SPX_WOTS_W = 16
        SPX_SHA512 = 1

        # Derived parameters
        SPX_ADDR_BYTES = 32
        SPX_WOTS_LOGW = 8 if SPX_WOTS_W == 256 else 4
        SPX_WOTS_LEN1 = 8 * SPX_N // SPX_WOTS_LOGW

        # ... Other derived parameters ...

        SPX_WOTS_LEN2 = 2 if SPX_WOTS_W == 256 else 4  # Adjust based on your precomputation

        SPX_WOTS_LEN = SPX_WOTS_LEN1 + SPX_WOTS_LEN2
        SPX_WOTS_BYTES = SPX_WOTS_LEN * SPX_N
        SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES

        # ... Define other parameters ...

        # Subtree size
        SPX_TREE_HEIGHT = SPX_FULL_HEIGHT // SPX_D

        if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT:
            raise ValueError("SPX_D should always divide SPX_FULL_HEIGHT")

    # key generation is the same as the original SPHINCS+ implementation - pyspx library
    def keygen(self, seed):
        """
        generate a public and private key pair according to pyspx library shake_256f
        :return: public key, private key
        """
        # expected sizes of (pk ,sk, sig): [64, 128, 49856]
        pk, sk = pyspx.shake_256f.generate_keypair(seed)
        return pk, sk

    # verify should function the same as described in pyspx library
    def verify(self, sig, msg, pk):
        """
        verify the signature of the message
        :param pk: public key - list of pk.seed and pk.root
        :param sig: signature
        :param msg: message
        :return: True/False
        """
        pk = (pk[0], pk[1])
        return pyspx.shake_256f.verify(sig, msg, pk)

    def toByte(self, x: int, y: int):
        """
        returns a y-byte string containing binary representation of x in big endian order
        :param x: non-negative integer
        :param y: non-negative integer
        :return: bytestring of length y
        """
        return x.to_bytes(y, byteorder='big')

    async def PRF_msg(self, sk, opt, msg):
        """
        pseudorandom function to generate randomness for the message compression
        :param sk: SK.prf
        :param opt: randomizer
        :param msg: message in Secure Object type
        :return: SHAKE(sk || opt || msg, 8n)
        """
        # TODO: check this function
        mes = mpc.np_concatenate((sk, opt, msg))
        return shake.shake(mes, 8 * self.n, 512)

    async def H_msg(self, R, pkseed, pkroot, msg):
        """
        hash function to generate the message digest and index
        :param R: randomness from PRF_msg
        :param pkseed: PK.seed
        :param pkroot: PK.root
        :param msg: message in Secure Object type
        :return: digest and index - SHAKE(R || PK.seed || PK.root || msg, 8m)
        """
        # TODO: check this function
        mes = mpc.np_concatenate((R, pkseed, pkroot, msg))
        return shake.shake(mes, 8 * self.m, 512)

    def PRF(self, pkseed, skseed, adrs):
        """
        pseudorandom function
        :param pkseed: SPHINCS+ public seed
        :param skseed: SPHINCS+ secret seed
        :param adrs: address
        :return: random value from SHAKE256(pk.seed || sk.seed || adrs, 8n)
        """
        mes = mpc.concatenate((pkseed, adrs, skseed))
        return shake.shake(mes, 8 * self.n, 512)

    def pad(self, x):
        """
        pad the array to the same length
        :param x: list of Secure Arrays (Secure Objects)
        :return: list of padded arrays
        """
        # TODO: fix this function
        max_len = max([i.size for i in x])
        #padding = util.to_secarray(arr)
        res = []
        for i in x:
            if len(i) < max_len:
                mpc.np_concatenate((i, np.array([0]*(max_len - i.size))))
            res.append(i)
        return res

    async def sign(self, M, SK):
        """
        sign the message M using secret key SK (All done using MPyC functions)
        :param M: message (secure object - secfld.array)
        :param SK: list of (SK.seed, SK.prf, PK.seed, PK.root) all of type secure objects
        :return: signature sign(M, SK) - still of secure object
        """
        # s is the signature for message M
        s = secfld.array(np.array([]))

        # initialization
        adrs = ADRS(self.toByte(0, 32))
        fors = FORS(self.n, self.k, self.t)

        print("adrs: ", adrs.adrs)
        print("fors: ", fors)

        # SK = [SK.seed, SK.prf, PK.seed, PK.root]
        skseed, skprf, pkseed, pkroot = SK

        for i in SK:
            print("SK: ", i)

        print("sign started")

        try:
            print("message: ", await mpc.output(M))
            print("sk: ", await mpc.output(skprf))
            print("sk: ", await mpc.output(skseed))
            print("sk: ", await mpc.output(pkseed))
            print("sk: ", await mpc.output(pkroot))
        except (ValueError, RuntimeError):
            print("FAIL HERE IN SIGNATURE ")

        # generate randomizer - default to pkseed and not randomized
        opt = pkseed
        print("opt: ", opt)
        if RANDOMIZE:
            opt = random.randint(0, 2**SPX_N)

        R = await self.PRF_msg(skprf, opt, M)

        # R should be concatenated to s, but since s is empty, we could just assign it directly
        s = mpc.np_copy(R)

        # compute message digest and index, digest is of type SecObj
        digest = self.H_msg(R, pkseed, pkroot, M)
        
        # TODO: check np_split function how it is used
        tmp_md = mpc.np_split(digest, floor((self.k * self.a + 7) / 8))
        tmp_idx_tree = mpc.np_split(digest, floor((self.h - (self.h / self.d) + 7) / 8))
        tmp_idx_leaf = mpc.np_split(digest, floor(((self.h / self.d) + 7) / 8))

        md = tmp_md[self.k * self.a]  # first ka bits of tmp_md
        idx_tree = tmp_idx_tree[self.h - (self.h / self.d)]  # first h - h/d bits of tmp_idx_tree
        idx_leaf = tmp_idx_leaf[self.h / self.d]  # first h/d bits of tmp_idx_leaf

        # FORS sign
        # TODO: implement ADRS and its functions!
        adrs.set_layer_addr(0)
        adrs.set_tree_addr(idx_tree)
        adrs.set_type(SPX_FORS_TREES)
        adrs.set_keypair_addr(idx_leaf)

        SIG_FORS = fors.fors_sign(md, skseed, pkseed, adrs)
        # TODO: pay attention to type of SIG_FORS and make sure concat works!
        s = mpc.np_concatenate((s, SIG_FORS))

        # get FORS public key
        PK_FORS = fors.fors_pkFromSig(SIG_FORS, md, pkseed, adrs)

        # sign FORS public key with HT
        adrs.set_type(2)  # 2 is for TREE
        ht = Hypertree(self.h, self.d, self.tau, self.w)
        SIG_HT = ht.ht_sign(PK_FORS, skseed, pkseed, idx_tree, idx_leaf)
        s = mpc.np_concatenate((s, SIG_HT))

        # signature consists of R, SIG_FORS, SIG_HT - all of type secure object
        sig = (s, M)
        return sig