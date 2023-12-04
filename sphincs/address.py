from sha2_offsets import *
from sphincs_params import *

# Specify which level of Merkle tree (the "layer") we're working on
def set_layer_addr(addr, layer):
    """
    set the layer at the address
    :param addr: address
    :param layer: the layer
    :return: changed address
    """
    addr[SPX_OFFSET_LAYER] = layer
    return addr

def set_tree_addr(addr, tree):
    """
    Specify which Merkle tree within the level (the "tree address") we're working on
    :param addr: tree address
    :param tree: merkle tree
    :return:
    """
    if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64:
        raise ValueError("Subtree addressing is currently limited to at most 2^64 trees")
    addr[SPX_OFFSET_TREE:SPX_OFFSET_TREE+8] = tree.to_bytes(8, 'big')
    return addr

#Specify the reason we'll use this address structure for, that is, what
#hash will we compute with it.  This is used so that unrelated types of
#hashes don't accidentally get the same address structure.  The type will be
#one of the SPX_ADDR_TYPE constants

def set_type(addr, type_val):
    addr_bytes = bytearray(addr)
    addr_bytes[SPX_OFFSET_TYPE] = type_val
    return bytes(addr_bytes)

def copy_subtree_addr(out, in_):
    """
    Copy the layer and tree fields of the address structure.  This is used
    when we're doing multiple types of hashes within the same Merkle tree
    :param out:
    :param in_:
    :return:
    """
    out[SPX_OFFSET_LAYER:SPX_OFFSET_TREE+8] = in_[SPX_OFFSET_LAYER:SPX_OFFSET_TREE+8]
    return out

# These functions are used for OTS addresses.

def set_keypair_addr(addr, keypair):
    """
    Specify which Merkle leaf we're working on; that is, which OTS keypair
    we're talking about.
    :param addr: address
    :param keypair: keypair
    :return: changed address
    """
    if SPX_FULL_HEIGHT/SPX_D > 8:
        # We have > 256 OTS at the bottom of the Merkle tree; to specify
        # which one, we'd need to express it in two bytes
        addr[SPX_OFFSET_KP_ADDR2] = keypair >> 8
    addr[SPX_OFFSET_KP_ADDR1] = keypair & 0xff
    return addr

def copy_keypair_addr(out, in_):
    """
    Copy the layer, tree and keypair fields of the address structure.  This is
    used when we're doing multiple things within the same OTS keypair
    :param out:
    :param in_:
    :return:
    """
    out[SPX_OFFSET_LAYER:SPX_OFFSET_KP_ADDR1+1] = in_[SPX_OFFSET_LAYER:SPX_OFFSET_KP_ADDR1+1]
    if SPX_FULL_HEIGHT/SPX_D > 8:
        out[SPX_OFFSET_KP_ADDR2] = in_[SPX_OFFSET_KP_ADDR2]
    return out

def set_chain_addr(addr, chain):
    """
    Specify which Merkle chain within the OTS we're working with
    (the chain address)
    :param addr: address
    :param chain: merkle chain
    :return: changed address
    """
    addr[SPX_OFFSET_CHAIN_ADDR] = chain
    return addr

def set_hash_addr(addr, hash):
    """
    Specify where in the Merkle chain we are
    (the hash address)
    :param addr: address
    :param hash: hash
    :return: changed address
    """
    addr[SPX_OFFSET_HASH_ADDR] = hash
    return addr

# These functions are used for all hash tree addresses (including FORS).

def set_tree_height(addr, tree_height):
    """
    Specify the height of the node in the Merkle/FORS tree we are in
    (the tree height)
    :param addr: address
    :param tree_height: tree height
    :return: changed address
    """
    addr[SPX_OFFSET_TREE_HGT] = tree_height
    return addr

def set_tree_index(addr, tree_index):
    """
    Specify the distance from the left edge of the node in the Merkle/FORS tree
    (the tree index)
    :param addr: address
    :param tree_index: tree index
    :return: changed address
    """
    addr[SPX_OFFSET_TREE_INDEX:SPX_OFFSET_TREE_INDEX+4] = tree_index.to_bytes(4, 'big')
    return addr
