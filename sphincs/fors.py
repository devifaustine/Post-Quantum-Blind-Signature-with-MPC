# implement FORS in SPHINCS+
import hashlib

from sphincs_params import *
from address import ADRS
from shake import SHAKE
from math import log, floor
import copy

# change to false if no log wanted
logging = True 

def xprint(string):
    if logging: 
        print(string)

shake = SHAKE()
y = 0
address = ADRS(y.to_bytes(32, 'big'))

# Note F(pkseed, adrs, m1) = shake256(pkseed||adrs||m1, 8n)

class FORS:
    def __init__(self, n, k, t):
        self.a = log(t, 2)
        self.n = n  # security parameter - length of pk, sk. sig in bytes
        self.k = k  # number of sk sets, trees and indices computed from input string
        self.t = t  # number of elements per sk set, leaves per hash tree and upper bound on index values

    def prf_addr(self, key, addr):
        """
        generate a pseudo-random function (PRF) from a key and an address
        :param key: key
        :param addr: address
        :return: PRF
        """
        mes = addr.get_address() + key
        res = shake.shake(mes, self.n, 512)
        sk = hashlib.shake_256(mes).digest(self.n)
        return res, sk

    def fors_SKgen(self, skseed, adrs, idx):
        """
        generate a secret key for a given index
        :param skseed: SK.seed of SPHINCS+
        :param adrs: address ADRS
        :param idx: sk index = i*t+j
        :return: secret key of FORS
        """
        skADRS = copy.deepcopy(adrs)  # copy address to create key gen address
        skADRS.set_type(3)  # 3 = FORS tree address, 4 = FORS tree roots compression address
        skADRS.set_keypair_addr(adrs.get_keypair_addr())

        skADRS.set_tree_height(0) # height of the tree
        idx_bytes = idx.to_bytes(4, 'big')
        skADRS.set_tree_index(idx_bytes)
        try: 
            sk = self.prf_addr(skseed, skADRS)  # generate sk using PRF
        except:
            xprint("fail during orf function for adrs.")
        xprint("fors sk generated")
        return sk[1]

    def F(self, pkseed, adrs, m1):
        """
        computes shake256(pkseed||adrs||m1, 8n)
        :param pkseed: public seed
        :param adrs: address ADRS
        :param m1:
        :return: the hash value
        """
        mes = pkseed + adrs.get_address() + m1
        hash = shake.shake(mes, 8 * self.n, 512)
        hash_org = hashlib.shake_256(mes).digest(8 * self.n)
        return hash, hash_org

    def Tk(self, pkseed, adrs, m):
        """
        computes shake256(pkseed || adrs || m, 8n)
        :param pkseed: SPHINCS+ public seed
        :param adrs: address
        :param m: message to be hashed
        :return: hashed values
        """
        mes = pkseed + adrs.get_address() + m
        hash = shake.shake(mes, 8 * self.n, 512)
        hash_org = hashlib.shake_256(mes).digest(8 * self.n)
        return hash, hash_org

    def H(self, pkseed, adrs, m):
        """
        computes shake256(pkseed||adrs||m, 8n)
        :param pkseed: public seed
        :param adrs: address ADRS
        :param m: m1 || m2
        :return: the hash value
        """
        mes = pkseed + adrs.get_address() + m
        hash = shake.shake(mes, 8 * self.n, 512)
        hash_org = hashlib.shake_256(mes).digest(8 * self.n)
        return hash, hash_org

    def get_height(self, byte):
        """
        get the height of a tree (represented in bytes)
        :param byte: tree
        :return: height of the tree (bytes) in int
        """
        # tree height is the second word of address ADRS (4 bytes)
        return len(byte)

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

            # TODO: find out how to break the loop - unendliche schleife jetzt
            # repeat whilst top node of the stack has the same height as node
            while len(stack) > 0 and self.get_height(stack[-1]) == self.get_height(node[1]):
                adrs.set_tree_index((int.from_bytes(adrs.get_tree_index(), 'big') - 1) // 2)
                node = self.H(pkseed, adrs, (stack.pop() + node[1]))
                adrs.set_tree_height(int.from_bytes(adrs.get_tree_height(), 'big') + 1)
            stack.append(node[1])
        xprint("fors treehash generated.")
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
        xprint("fors pk generated.")
        return pk[1]

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
            # convert message m to bits
            m_bits = ''.join(format(byte, '08b') for byte in m)
            # get next index
            idx_start = int(i * (log(self.t, 2)))
            idx_end = int((i + 1) * (log(self.t, 2)))
            idx = m_bits[idx_start:idx_end] # index is bytestring
            int_id = int(idx, 2)

            # pick private key element
            sk_element = self.fors_SKgen(skseed, adrs, i * self.t + int_id)
            sig_fors += sk_element

            # compute auth path
            auth = b''
            for j in range(int(self.a)):
                s = floor(int_id / (2 ** j)) ^ 1
                auth += self.fors_treehash(skseed, i * self.t + s * (2 ** j), j, pkseed, adrs)

            sig_fors += auth
        xprint("fors signature generated.")
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
        node = []
        root = []
        # compute roots
        for i in range(self.k):
            # get the next index from bits i*log(t) to (i+1)*log(t) - 1 of message m
            # convert message to bit repr
            m_bits = ''.join(format(byte, '08b') for byte in m)
            idx_start = i * int(log(self.t, 2))
            idx_end = (i + 1) * int(log(self.t, 2))
            idx = m_bits[idx_start:idx_end]
            idx_int = int(idx, 2)

            # compute leaf
            sk = sig_fors[i * 2 * self.n: (2 * i + 1) * self.n]
            adrs.set_tree_height(0)
            adrs.set_tree_index(idx_int + self.t * i)
            node.append(self.F(pkseed, adrs, sk))

            # compute root from leaf and auth
            auth = sig_fors[(i + 1) * self.n:(i + 1) * (self.n * 2)]
            adrs.set_tree_index(i * self.t + idx_int)
            for j in range(int(self.a)):
                adrs.set_tree_height(j+1)
                if floor(idx_int / ( 2 ** j)) % 2 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node.append(self.H(pkseed, adrs, (node[0]+auth[j])))
                else:
                    adrs.set_tree_index((adrs.get_tree_index() -1) / 2)
                    node.append(self.H(pkseed, adrs, (auth[j] + node[0])))
                node[0] = node[1]
            root.append(node[0])
        forspkADRS = copy.deepcopy(adrs)  # copy address to create FTS pubkey address

        forspkADRS.set_type(4)  # 4 = FORS roots
        forspkADRS.set_keypair_addr(adrs.get_keypair_addr())
        pk = self.Tk(pkseed, forspkADRS, root)
        xprint("fors verification done.")
        return pk[1]

