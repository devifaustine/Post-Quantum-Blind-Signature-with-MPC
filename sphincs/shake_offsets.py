"""
Offsets of various fields in the address structure when we use SHA2 as
the SPHINCS+ hash function
"""

SPX_OFFSET_LAYER = 0   # The byte used to specify the Merkle tree layer
SPX_OFFSET_TREE = 1   # The start of the 8 byte field used to specify the tree
SPX_OFFSET_TYPE = 9   # The byte used to specify the hash type (reason)
SPX_OFFSET_KP_ADDR2 = 12  # The high byte used to specify the key pair (which one-time signature)
SPX_OFFSET_KP_ADDR1 = 13  # The low byte used to specify the key pair
SPX_OFFSET_CHAIN_ADDR = 17  # The byte used to specify the chain address (which Winternitz chain)
SPX_OFFSET_HASH_ADDR = 21  # The byte used to specify the hash address (where in the Winternitz chain)
SPX_OFFSET_TREE_HGT = 17  # The byte used to specify the height of this node in the FORS or Merkle tree
SPX_OFFSET_TREE_INDEX = 18  # The start of the 4 byte field used to specify the node in the FORS or Merkle tree
SPX_SHA2 = 1
