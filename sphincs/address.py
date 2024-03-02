from shake_offsets import *
from sphincs_params import *

"""
Usage: 
from address import ADRS 
adrs = ADRS() 
adrs.setType(adrs.WOTS_HASH)
print("adrs =", adrs.toHex())
adrs = ADRS.fromHex("1528daecdc86eb8761030000000200000002000000d")

1 word = 32 bits = 4 bytes 

Format: 
layer   treeaddr    type    word1       word2       word3
[1]     [3]         [1]     [1]         [1]         [1]

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
    def __init__(self, adrs=b''):
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
        if adrs != b'':
            assert len(adrs) == 32
            self.adrs = adrs
        else:
            self.adrs = b'\x00' * SPX_ADDR_BYTES
        self.adrs_type = adrs[SPX_OFFSET_TYPE:SPX_OFFSET_TYPE + 4]
        self.layer = adrs[SPX_OFFSET_LAYER:SPX_OFFSET_LAYER + 4]
        self.treeaddr = adrs[SPX_OFFSET_TREE:SPX_OFFSET_TREE + 8]
        self.word1 = adrs[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX + 4]
        self.word2 = adrs[SPX_OFFSET_TREE_INDEX + 4:SPX_OFFSET_TREE_INDEX + 8]
        self.word3 = adrs[SPX_OFFSET_TREE_INDEX + 8:SPX_OFFSET_TREE_INDEX + 12]

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

    def __str__(self):
        # Convert bytes to string using decode
        return self.adrs.decode('utf-8')

    def __repr__(self):
        """
        return the address as a byte representation
        :return: address in bytes
        """
        return self.adrs

    def get_address(self):
        """
        get the address
        :return:
        """
        return self.adrs

    def update_adrs(self):
        """
        update the address adrs from its components
        :return: self
        """
        self.adrs = self.layer.to_bytes(4, 'big') + self.treeaddr + self.adrs_type + self.word1 + self.word2 + self.word3
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

    def copy(self, adrs):
        """
        copy the address
        :return: the copied address
        """
        new_adr = ADRS(adrs)
        print("new address: ", new_adr)
        return new_adr

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
        return self


    # Specify which level of Merkle tree (the "layer") we're working on
    def set_layer_addr(self, layer):
        """
        set the layer at the address
        :param layer: the layer
        :return:
        """
        self.layer = layer
        self.update_adrs()
        return self

    def set_tree_addr(self, tree):
        """
        Specify which Merkle tree within the level (the "tree address") we're working on
        :param tree: merkle tree
        :return:
        """
        if not isinstance(tree, bytes):
            tree = tree.to_bytes(8, 'big')
        #if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64:
        #    raise ValueError("Subtree addressing is currently limited to at most 2^64 trees")
        self.treeaddr = tree
        self.update_adrs()
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
        self.word1 = keypair
        self.update_adrs()
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
        self.word2 = chain
        self.update_adrs()
        return self

    def set_hash_addr(self, hash_):
        """
        Specify where in the Merkle chain we are
        (the hash address)
        :param hash_: hash
        :return:
        """
        self.word3 = hash_
        self.update_adrs()
        return self

    # These functions are used for all hash tree addresses (including FORS).

    def get_keypair_addr(self):
        """
        Get the key pair address
        :return: key pair address
        """
        return self.word1

    def set_tree_height(self, tree_height):
        """
        Specify the height of the node in the Merkle/FORS tree we are in
        (the tree height)
        :param tree_height: tree height
        :return: changed address
        """
        if isinstance(tree_height, int):
            tree_height = tree_height.to_bytes(4, 'big')
        self.word2 = tree_height
        self.update_adrs()
        return self

    def set_tree_index(self, tree_index):
        """
        Specify the distance from the left edge of the node in the Merkle/FORS tree
        (the tree index)
        :param tree_index: tree index
        :return: changed address
        """
        if isinstance(tree_index, int):
            tree_index = tree_index.to_bytes(4, 'big')
        self.word3 = tree_index
        self.update_adrs()
        return self

    def get_tree_index(self):
        """
        Get the tree index
        :return: tree index
        """
        return self.word3
