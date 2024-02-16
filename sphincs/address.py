from sha2_offsets import *
from sphincs_params import *

# TODO: reform this to suit secure objects
# TODO: remove these offsets as it is already in sha2 offsets
SPX_OFFSET_LAYER = 0   # The byte used to specify the Merkle tree layer
SPX_OFFSET_TREE = 1   # The start of the 8 byte field used to specify the tree
SPX_OFFSET_TYPE = 9   # The byte used to specify the hash type (reason)
SPX_OFFSET_KP_ADDR2 = 12  # The high byte used to specify the key pair (which one-time signature)
SPX_OFFSET_KP_ADDR1 = 13  # The low byte used to specify the key pair
SPX_OFFSET_CHAIN_ADDR = 17  # The byte used to specify the chain address (which Winternitz chain)
SPX_OFFSET_TREE_HGT = 17  # The byte used to specify the height of this node in the FORS or Merkle tree
SPX_OFFSET_TREE_INDEX = 18  # The start of the 4 byte field used to specify the node in the FORS or Merkle tree
SPX_OFFSET_HASH_ADDR = 21  # The byte used to specify the hash address (where in the Winternitz chain)

class ADRS:
    def __init__(self, adrs):
        """
        initializes the address
        :param adrs: bytestring of size SPX_ADDR_BYTES (32) or None
        """
        assert len(adrs) == SPX_ADDR_BYTES, "Address must be " + str(SPX_ADDR_BYTES) + " bytes long!"
        self.adrs = adrs

        # TODO: fix this - find out difference between type and layer!
        if adrs != None:
            self.type = adrs[SPX_OFFSET_TYPE]
            self.layer = adrs[SPX_OFFSET_LAYER]
            self.treeadr = adrs[SPX_OFFSET_TREE:SPX_OFFSET_TREE+8]
            self.keypairadr = adrs[SPX_OFFSET_KP_ADDR1:SPX_OFFSET_KP_ADDR2+1]
            self.chainadr = adrs[SPX_OFFSET_CHAIN_ADDR]
            self.hashadr = adrs[SPX_OFFSET_HASH_ADDR]
        else:
            self.type = None # 1 byte
            self.layer = None # 1 byte
            self.treeadr = None # 8 bytes
            self.keypairadr = None # 2 bytes
            self.chainadr = None # 4 bytes
            self.hashadr = None # 4 bytes

    def __repr__(self):
        # TODO: fix this (still not correct) - find out difference between type and layer!
        # every ADRS begins with type (layer address)
        res = self.type.to_bytes(1, 'big')
        if self.type == 0:
            # WOTS+ hash address (type + keypairadr + chainadr + hashadr)
            res += self.keypairadr.to_bytes(2, 'big')
            res += self.chainadr.to_bytes(4, 'big')
        elif self.type == 1:
            # WOTS+ public key compression address (type + keypairadr + padding 0)
            res += self.keypairadr.to_bytes(2, 'big')
            res += self.pad(0, 4)
        elif self.type == 2:
            # hash tree address (type + padding 0 + tree height + tree index)
            pass
        elif self.type == 3:
            # FORS tree address (type + keypairadr + tree height + tree index)
            pass
        elif self.type == 4:
            # FORS tree roots compression address (type + keypairadr + padding 0)
            pass
        elif self.type == 5:
            # WOTS+ key generation address (type + keypairadr + chainadr + hashadr)
            pass
        return res
        raise NotImplementedError("Not yet implemented")

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
        return self
