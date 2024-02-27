from shake_offsets import *
from sphincs_params import *

"""
Usage: 
from address import ADRS 
adrs = ADRS() 
adrs.setType(adrs.WOTS_HASH)
print("adrs =", adrs.toHex())
adrs = ADRS.fromHex("1528daecdc86eb8761030000000200000002000000d")

Format: 
layer   treeaddr    type    word1       word2       word3
[1]     [8]         [1]     [4]         [4]         [4]

0       1            9          10           14           18 # byte offsets
0       2            18         20           28           36  # hex offsets

-----------------------------------------------------------------------------------
Type                         |   Word 1  |   Word 2  |   Word 3  |   Type Constant
-----------------------------------------------------------------------------------
0 WOTS+ hash address            keypairadr  chainadr    hashadr     WOTS_HASH
1 WOTS+ pk comp addr            keypairadr      0           0       WOTS_PK
2 Hash tree address             0           tree ht    tree index   TREE
3 FORS tree address             keypairadr  tree ht    tree index   FORS_TREE
4 FORS tree root comp addr      keypairadr      0           0       FORS_ROOTS
5 WOTS+ key gen addr            keypairadr  chainadr    hashadr     WOTS_KEY
6 WOTS+ key comp addr           keypairadr      0           0       WOTS_KEY_COMP
"""

class ADRS:
    def __init__(self, adrs=b'', adrs_type=0, layer=0, treeaddr=0, word1=0, word2=0, word3=0):
        """
        initializes the address
        :param adrs: bytestring of size SPX_ADDR_BYTES (32) or None
        :param adrs_type: bytestring for address type
        :param layer: bytestring representing layer of the tree in HT
        :param treeaddr: bytestring representation of the tree adress
        :param word1: bytes
        :param word2: bytes
        :param word3: bytes
        """
        assert len(adrs) == 32
        if adrs != b'':
            self.adrs = adrs
            self.adrs_type = int.from_bytes(adrs[SPX_OFFSET_TYPE], byteorder='big')
            self.layer = int.from_bytes(adrs[SPX_OFFSET_LAYER], byteorder='big')
            self.treeaddr = int.from_bytes(adrs[SPX_OFFSET_TREE:SPX_OFFSET_TREE+8], byteorder='big')
            self.word1 = int.from_bytes(adrs[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX+4], byteorder='big')
            self.word2 = int.from_bytes(adrs[SPX_OFFSET_TREE_INDEX+4:SPX_OFFSET_TREE_INDEX+8], byteorder='big')
            self.word3 = int.from_bytes(adrs[SPX_OFFSET_TREE_INDEX+8:SPX_OFFSET_TREE_INDEX+12], byteorder='big')
        else:
            self.adrs = layer.to_bytes(1, 'big') + treeaddr.to_bytes(8, 'big') + \
                        adrs_type.to_bytes(1, 'big') + word1.to_bytes(4, 'big') + \
                        word2.to_bytes(4, 'big') + word3.to_bytes(4, 'big')
            self.adrs_type = adrs_type
            self.layer = layer
            self.treeaddr = treeaddr
            self.word1 = word1
            self.word2 = word2
            self.word3 = word3

    def toHex(self):
        """
        return 32-byte address as a hex string
        :return: hex repr of address
        """
        # TODO: check this again
        treeaddr_hex = format(self.treeaddr, f'x').zfill(16)
        return (format(self.layer, f'x').zfill(2) + treeaddr_hex + format(self.adrs_type, f'x').zfill(2) +
                format(self.word1, f'x').zfill(8) + format(self.word2, f'x').zfill(8) +
                format(self.word3, f'x').zfill(8))


    def __repr__(self):
        """
        return the address as a byte representation
        :return: address in bytes
        """
        return self.adrs

    def update_adrs(self):
        """
        update the address adrs from its components
        :return: self
        """
        self.adrs = str(self.layer) + str(self.treeaddr) + str(self.adrs_type) + str(self.word1) + str(self.word2) + str(self.word3)
        return self

    def update_comp(self):
        """
        update the components of the address from the address adrs
        :return: self
        """
        self.layer = int(self.adrs[0:2])
        self.treeaddr = int(self.adrs[2:18])
        self.adrs_type = int(self.adrs[18:20])
        self.word1 = int(self.adrs[20:28])
        self.word2 = int(self.adrs[28:36])
        self.word3 = int(self.adrs[36:])
        return self

    @classmethod
    def fromHex(cls, hex_str):
        """
        set the address from hex string
        :param hex_str: hex string
        :return: None
        """
        layer = int(hex_str[0:2], 16)
        treeaddr = int(hex_str[2:18], 16)
        adrs_type = int(hex_str[18:20], 16)
        word1 = int(hex_str[20:28], 16)
        word2 = int(hex_str[28:36], 16)
        word3 = int(hex_str[36:], 16)
        return cls(b'', adrs_type, layer, treeaddr, word1, word2, word3)

    def copy(self):
        """
        copy the address
        :return: the copied address
        """
        return ADRS(self.adrs)

    def pad(self, value, length):
        """
        pads the value to the specified length
        :param value: typically bytes/string
        :param length: integer
        :return: the padding in bytes
        """
        return value.to_bytes(length, 'big')

    # TODO: check the functions below again!

    def set_type(self, type_):
        """
        sets the type of ADRS based on SPHINCS+ docs
        :param type_: integer value from {0...6}
        :return: None
        """
        self.type = type_
        self.update_adrs()


    # Specify which level of Merkle tree (the "layer") we're working on
    def set_layer_addr(self, layer):
        """
        set the layer at the address
        :param layer: the layer
        :return:
        """
        self.adrs[SPX_OFFSET_LAYER] = layer
        return self

    def set_tree_addr(self, tree):
        """
        Specify which Merkle tree within the level (the "tree address") we're working on
        :param tree: merkle tree
        :return:
        """
        if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64:
            raise ValueError("Subtree addressing is currently limited to at most 2^64 trees")
        self.adrs[SPX_OFFSET_TREE:SPX_OFFSET_TREE+8] = tree.to_bytes(8, 'big')
        return self


    def copy_subtree_addr(self, in_):
        """
        Copy the layer and tree fields of the address structure.  This is used
        when we're doing multiple types of hashes within the same Merkle tree
        :param in_: copy from address
        :return:
        """
        self.adrs[SPX_OFFSET_LAYER:SPX_OFFSET_TREE+8] = in_[SPX_OFFSET_LAYER:SPX_OFFSET_TREE+8]
        return self

    # These functions are used for OTS addresses.

    def set_keypair_addr(self, keypair):
        """
        Specify which Merkle leaf we're working on; that is, which OTS keypair
        we're talking about.
        :param keypair: keypair
        :return:
        """
        if SPX_FULL_HEIGHT/SPX_D > 8:
            # We have > 256 OTS at the bottom of the Merkle tree; to specify
            # which one, we'd need to express it in two bytes
            self.adrs[SPX_OFFSET_KP_ADDR2] = keypair >> 8
        self.adrs[SPX_OFFSET_KP_ADDR1] = keypair & 0xff
        return self

    def copy_keypair_addr(self, in_):
        """
        Copy the layer, tree and keypair fields of the address structure.  This is
        used when we're doing multiple things within the same OTS keypair
        :param in_: copy from address
        :return:
        """
        self.adrs[SPX_OFFSET_LAYER:SPX_OFFSET_KP_ADDR1+1] = in_[SPX_OFFSET_LAYER:SPX_OFFSET_KP_ADDR1+1]
        if SPX_FULL_HEIGHT/SPX_D > 8:
            self.adrs[SPX_OFFSET_KP_ADDR2] = in_[SPX_OFFSET_KP_ADDR2]
        return self

    def set_chain_addr(self, chain):
        """
        Specify which Merkle chain within the OTS we're working with
        (the chain address)
        :param chain: merkle chain
        :return:
        """
        self.adrs[SPX_OFFSET_CHAIN_ADDR] = chain
        return self

    def set_hash_addr(self, hash):
        """
        Specify where in the Merkle chain we are
        (the hash address)
        :param hash: hash
        :return:
        """
        self.adrs[SPX_OFFSET_HASH_ADDR] = hash
        return self

    # These functions are used for all hash tree addresses (including FORS).

    def get_keypair_addr(self):
        """
        Get the key pair address
        :return: key pair address
        """
        return self.adrs[SPX_OFFSET_KP_ADDR1]

    def set_tree_height(self, tree_height):
        """
        Specify the height of the node in the Merkle/FORS tree we are in
        (the tree height)
        :param tree_height: tree height
        :return: changed address
        """
        self.adrs[SPX_OFFSET_TREE_HGT] = tree_height
        return self

    def set_tree_index(self, tree_index):
        """
        Specify the distance from the left edge of the node in the Merkle/FORS tree
        (the tree index)
        :param tree_index: tree index
        :return: changed address
        """
        self.adrs[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX+4] = tree_index.to_bytes(4, 'big')
        self.update_comp()
        return self

    def get_tree_index(self):
        """
        Get the tree index
        :return: tree index
        """
        return int.from_bytes(self.adrs[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX+4], 'big')
