# implements the main tree / SPHINCS+ Hypertree

from wots import WOTS
from xmss import XMSS
from address import ADRS
from utils import UTILS
import time

util = UTILS()
# set logging to False if you don't want to print debug messages
logging = True
timer = 10

def xprint(string):
    if logging:
        print(string)

class Hypertree():
    def __init__(self, n=32, h=68, d=17, w=16):
        """
        Initializes SPHINCS+ Hypertree according to docs

        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- number of layers in the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        """
        self.n = n
        self.h = h  # height of the SPHINCS+ HT
        self.d = d
        self.ht = h // d  # height of the tree in HT
        self.w = w
        self.wots = WOTS(n, w)
        self.xmss = XMSS(self.ht, self.n, self.w)

    def ht_PKgen(self, skseed, pkseed):
        """
        generates the public key of the hypertree
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :return: HT public key
        """
        adrs = ADRS(util.toByte(0, 32))
        adrs.set_layer_addr(self.d - 1)
        adrs.set_tree_addr(0)
        root = self.xmss.xmss_pkgen(skseed, pkseed, adrs)
        xprint("Hypertree public key generated.")
        return root

    def ht_sign(self, m, skseed, pkseed, id_tree, id_leaf):
        """
        HT signature SIG_HT generation for a message m
        :param m: message
        :param skseed: SPHINCS+ secret seed
        :param pkseed: SPHINCS+ public seed
        :param id_tree: index of the tree
        :param id_leaf: index of the leaf
        :return: HT signature
        """
        xprint("Begin HT signing. ")
        # init
        adrs = ADRS(util.toByte(0, 32))
        sig_ht = b''

        # sign
        adrs.set_layer_addr(0)
        adrs.set_tree_addr(id_tree)
        sig_tmp = self.xmss.xmss_sign(m, skseed, id_leaf, pkseed, adrs)
        sig_ht += sig_tmp
        root = self.xmss.xmss_pk_from_sig(id_leaf, sig_tmp, m, pkseed, adrs)

        start = time.time()
        for i in range(self.d):
            id_leaf = self.h // self.d  # least significatn bits of id_tree
            id_tree = (self.h - (i + 1) * (self.h / self.d))  # most significant bits of id_tree
            adrs.set_layer_addr(i)
            adrs.set_tree_addr(int(id_tree))
            sig_tmp = self.xmss.xmss_sign(root, skseed, id_leaf, pkseed, adrs)
            sig_ht += sig_tmp
            if i < self.d - 1:
                root = self.xmss.xmss_pk_from_sig(id_leaf, sig_tmp, root, pkseed, adrs)
            if time.time()-start > timer:
                xprint("Hypertree signature generation is taking too long.")
                break
        xprint("Hypertree signature generated.")
        return sig_ht, util.to_secarray(sig_ht)


    # signature verification
    def ht_verify(self, m, sig_ht, pkseed, id_tree, id_leaf, pk_ht):
        """
        verify the HT signature on m
        :param m: message
        :param sig_ht: HT signature
        :param pkseed: SPHINCS+ public seed
        :param id_tree: index of tree
        :param id_leaf: index of leaf
        :param pk_ht: HT public key
        :return: True/False
        """
        # TODO: check this function
        # init
        adrs = ADRS(util.toByte(0, 32))

        # verify
        idx = self.h // self.d * self.n
        sig_tmp = sig_ht[:idx]  # gets the first XMSS signature of HT
        adrs.set_layer_addr(0)
        adrs.set_tree_addr(id_tree)
        node = self.xmss.xmss_pk_from_sig(id_leaf, sig_tmp, m, pkseed, adrs)
        for i in range(self.d):
            id_leaf = self.h // self.d
            id_tree = (self.h - (i + 1) * (self.h / self.d))
            sig_tmp = sig_ht[idx:idx + (i * self.n)]
            adrs.set_layer_addr(i)
            adrs.set_tree_addr(id_tree)
            node = self.xmss.xmss_pk_from_sig(id_leaf, sig_tmp, node, pkseed, adrs)

        xprint("HT verification process is done.")

        if node == pk_ht:
            return True
        else:
            return False
