from sha2_offsets import *
from sphincs_params import *

#TODO: reform this to suit secure objects

class ADRS:
    def __init__(self):
        # initializes the address for size SPX_ADDR_BYTES
        self.adrs = bytearray(SPX_ADDR_BYTES)
        self.type = None

    # TODO: check the functions below again!

    def set_type(self, type_):
        """
        sets the type of ADRS based on SPHINCS+ docs
        :param type_: integer value from {0...6}
        :return: None
        """
        self.type = type_


    # Specify which level of Merkle tree (the "layer") we're working on
    def set_layer_addr(self, layer):
        """
        set the layer at the address
        :param layer: the layer
        :return: changed address
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
        :param in_:
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
        :return: changed address
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
        :param in_:
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
        :return: changed address
        """
        self.adrs[SPX_OFFSET_CHAIN_ADDR] = chain
        return self

    def set_hash_addr(self, hash):
        """
        Specify where in the Merkle chain we are
        (the hash address)
        :param hash: hash
        :return: changed address
        """
        self.adrs[SPX_OFFSET_HASH_ADDR] = hash
        return self

    # These functions are used for all hash tree addresses (including FORS).

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
        return self
