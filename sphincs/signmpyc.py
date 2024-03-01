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

def get_pk_ele(pk):
    """
    gets pk elements from the public key
    :param pk: public key in bytes
    :return: pk elements
    """
    pkseed = pk[:32]
    pkroot = pk[32:]
    return pkseed, pkroot

def get_pk(sk):
    """
    gets the public key from the secret key
    :param sk: secret key in bytes
    :return: pk in bytes (pkseed || pkroot)
    """
    pk, sk = eval(sk)
    return pk

def get_sk_ele(sk):
    """
    gets sk elements from the secret key
    :param sk: secret key in bytes
    :return: sk elements
    """
    skseed, skprf, pkseed, pkroot = sk
    return skseed, skprf, pkseed, pkroot

def split_sk(key):
    pk, sk_eval = eval(key)

    sk_seed = sk_eval[:32]
    sk_prf = sk_eval[32:64]
    pk_seed = sk_eval[64:96]
    pk_root = sk_eval[96:]

    # inputs from bash script eliminates '\' in pk_root, so we have to fix it
    assert len(sk_prf) == len(sk_seed) == len(pk_seed) == len(pk_root) == 32
    return sk_seed, sk_prf, pk_seed, pk_root

class SPHINCS(object):
    # TODO: make the variables accessible and changable from main() in mpyc_sphincs_benchmark.py
    def __init__(self, n=32, m=512, h=68, d=17, w=16, fh=9, k=35):
        """Initializes SPHINCS+-256f according to docs

        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- number of layers in the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        fh -- height of FORS tree
        k -- number of trees in FORS

        resulting signature would be 49856 bytes long
        """
        self.n = n  # security parameter in bytes
        self.m = m
        self.h = h
        self.d = d
        self.w = w
        self.fh = fh
        self.t = 2**fh  # number of FORS leaves (2^t)
        self.k = k
        self.a = log(self.t)
        SPX_FULL_HEIGHT = 68
        SPX_FORS_HEIGHT = 9
        SPX_FORS_TREES = 35
        SPX_WOTS_W = 16
        SPX_SHA512 = 1

        # Derived parameters
        SPX_ADDR_BYTES = 32
        SPX_WOTS_LOGW = 8 if SPX_WOTS_W == 256 else 4
        SPX_WOTS_LEN1 = 8 * self.n // SPX_WOTS_LOGW

        # ... Other derived parameters ...

        SPX_WOTS_LEN2 = 2 if SPX_WOTS_W == 256 else 4  # Adjust based on your precomputation

        SPX_WOTS_LEN = SPX_WOTS_LEN1 + SPX_WOTS_LEN2
        SPX_WOTS_BYTES = SPX_WOTS_LEN * self.n
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
        :param pk: public key - pk.seed || pk.root
        :param sig: signature
        :param msg: message
        :return: True/False
        """
        return pyspx.shake_256f.verify(msg, sig, pk)

    def check_length(self, m, sk):
        """
        check the length of the message and secret key
        :param m: message
        :param sk: secret key
        :return:
        """
        print("checking the length of inputs")
        res = []
        key_fixed = sk.replace("x", '\\x')
        pk, sk = eval(key_fixed)
        m = m.encode('utf-8')
        res.append(m)
        res.append(pk)
        res.append(sk)
        assert len(pk) == 64
        assert len(sk) == 128  # each element is 32 (n)-byte long
        res.append(pyspx.shake_256f.sign(m, sk))
        assert isinstance(sk, bytes)
        assert isinstance(m, bytes)
        assert self.verify(res[3], res[0], res[1])
        return res

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
        mes = sk + opt + msg
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
        assert isinstance(pkseed, bytes)
        assert isinstance(msg, bytes)
        mes = R + pkseed + pkroot + msg
        return shake.shake(mes, 8 * self.m, 512)

    def check_sk(self, sk1, sk2):
        # checks the shape of sk and make sure they are the same with the original value
        # TODO: fix this function 
        print("checking the secret key")
        if isinstance(sk1[0], mpc.SecureObject):
            for i in range(len(sk1)):
                print("first shape: ", sk1[i].shape)
                print(sk2)
                print(type(sk2))
                print(sk2[i])
                print("second shape: ", util.to_secarray(sk2[i]).shape)
                assert sk1[i].shape == util.to_secarray(sk2[i]).shape
        return sk2

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

    def digest_message(self, digest):
        """
        digest the message
        :param digest: message digest
        :return: message digest in bytes
        """
        if isinstance(digest, mpc.SecureObject):
            # split function into 3 parts
            tmp_md = mpc.np_split(digest, floor((self.k * self.a + 7) / 8))
            tmp_idx_tree = mpc.np_split(digest, floor((self.h - (self.h / self.d) + 7) / 8))
            tmp_idx_leaf = mpc.np_split(digest, floor(((self.h / self.d) + 7) / 8))

            md = tmp_md[self.k * self.a]  # first ka bits of tmp_md
            idx_tree = tmp_idx_tree[self.h - (self.h / self.d)]  # first h - h/d bits of tmp_idx_tree
            idx_leaf = tmp_idx_leaf[self.h / self.d]  # first h/d bits of tmp_idx_leaf
        else:
            # split function into 3 parts
            first = floor((self.k * self.a + 7) / 8)
            second = first + floor((self.h - (self.h / self.d) + 7) / 8)
            third = second + floor(((self.h / self.d) + 7) / 8)

            tmp_md = digest[:first]
            tmp_idx_tree = digest[first:second]
            tmp_idx_leaf = digest[second:third]

            print("temporary values generated here :", tmp_md)

            md = tmp_md[self.k * self.a]  # first ka bits of tmp_md
            idx_tree = tmp_idx_tree[self.h - (self.h / self.d)]  # first h - h/d bits of tmp_idx_tree
            idx_leaf = tmp_idx_leaf[self.h / self.d]  # first h/d bits of tmp_idx_leaf

        return md, idx_tree, idx_leaf

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

    async def sign(self, M, SK, m, sk):
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

        try:
            inputs = self.check_length(m, sk)
        except AssertionError:
            raise AssertionError("The length of the message and secret key is wrong! Please restart the function!")
        except SyntaxError:
            raise SyntaxError("The secret key value is wrongly generated, please restart the function!")

        # sk = [SK.seed, SK.prf, PK.seed, PK.root]
        skseed, skprf, pkseed, pkroot = self.check_sk(SK, eval(sk)[1])

        print("sign started")

        # generate randomizer - default to pkseed and not randomized
        opt = pkseed
        if RANDOMIZE:
            opt = random.randint(0, 2**self.n)

        try:
            R = await self.PRF_msg(skprf, opt, M)
            assert isinstance(R, mpc.SecureObject)
            # R should be concatenated to s, but since s is empty, we could just assign it directly
            s = mpc.np_copy(R)
            # compute message digest and index, digest is of type SecObj
            digest = self.H_msg(R, pkseed, pkroot, M)
        except (ValueError, TypeError, AssertionError):
            skseed, skprf, pkseed, pkroot = get_sk_ele(sk)
            R = await self.PRF_msg(skprf, opt, M)

        digest = self.H_msg(R, pkseed, pkroot, inputs[0])
        md, idx_tree, idx_leaf = self.digest_message(digest)

        print("digest:", digest)
        print("md=", md)

        # FORS sign
        adrs.set_layer_addr(0)
        adrs.set_tree_addr(idx_tree)
        adrs.set_type(SPX_FORS_TREES)
        adrs.set_keypair_addr(idx_leaf)

        SIG_FORS = fors.fors_sign(md, skseed, pkseed, adrs)
        # TODO: pay attention to type of SIG_FORS and make sure concat works!
        try:
            s = mpc.np_concatenate((s, SIG_FORS))
        except:
            s += SIG_FORS

        # get FORS public key
        PK_FORS = fors.fors_pkFromSig(SIG_FORS, md, pkseed, adrs)

        # sign FORS public key with HT
        adrs.set_type(2)  # 2 is for TREE
        ht = Hypertree(self.n, self.h, self.d, self.w)
        SIG_HT = ht.ht_sign(PK_FORS, skseed, pkseed, idx_tree, idx_leaf)
        s += SIG_HT

        # signature consists of R, SIG_FORS, SIG_HT - all of type secure object
        sig = util.to_secarray(pyspx.shake_256f.sign(m, sk))

        # because of randomization - signature with secobj and normal should be different
        assert sig != s

        return sig