"""
Offsets of various fields in the address structure when we use SHAKE as
the SPHINCS+ hash function
"""

SPX_OFFSET_LAYER = 3   # The byte used to specify the Merkle tree layer 
SPX_OFFSET_TREE = 8   # The start of the 8 byte field used to specify the tree 
SPX_OFFSET_TYPE = 19  # The byte used to specify the hash type (reason)
SPX_OFFSET_KP_ADDR2 = 22  # The high byte used to specify the key pair (which one-time signature)
SPX_OFFSET_KP_ADDR1 = 23  # The low byte used to specify the key pair
SPX_OFFSET_CHAIN_ADDR = 27  # The byte used to specify the chain address (which Winternitz chain)
SPX_OFFSET_HASH_ADDR = 31  # The byte used to specify the hash address (where in the Winternitz chain)
SPX_OFFSET_TREE_HGT = 27  # The byte used to specify the height of this node in the FORS or Merkle tree
SPX_OFFSET_TREE_INDEX = 28 # The start of the 4 byte field used to specify the node in the FORS or Merkle tree

SPX_SHAKE = 1