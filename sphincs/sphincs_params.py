# sphincs_params.py
from sha2_offsets import *

# Constants
SPX_N = 32
SPX_FULL_HEIGHT = 68
SPX_D = 17
SPX_FORS_HEIGHT = 9
SPX_FORS_TREES = 35
SPX_WOTS_W = 16
SPX_SHA512 = 1

# Derived parameters
SPX_ADDR_BYTES = 32
SPX_WOTS_LOGW = 8 if SPX_WOTS_W == 256 else 4
SPX_WOTS_LEN1 = 8 * SPX_N // SPX_WOTS_LOGW

# ... Other derived parameters ...

SPX_WOTS_LEN2 = 2 if SPX_WOTS_W == 256 else 4  # Adjust based on your precomputation

SPX_WOTS_LEN = SPX_WOTS_LEN1 + SPX_WOTS_LEN2
SPX_WOTS_BYTES = SPX_WOTS_LEN * SPX_N
SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES

# ... Define other parameters ...

# Subtree size
SPX_TREE_HEIGHT = SPX_FULL_HEIGHT // SPX_D

if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT:
    raise ValueError("SPX_D should always divide SPX_FULL_HEIGHT")

# ... Define other parameters ...

# FORS parameters
SPX_FORS_MSG_BYTES = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) // 8
SPX_FORS_BYTES = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N
SPX_FORS_PK_BYTES = SPX_N

# Resulting SPX sizes
SPX_BYTES = SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N
SPX_PK_BYTES = 2 * SPX_N
SPX_SK_BYTES = 2 * SPX_N + SPX_PK_BYTES

# You can use these constants in other parts of your Python code as needed.
