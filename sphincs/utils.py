from sphincs.sphincs_params import *
from address import *
from sphincs.hash_sha2 import *
from thash_sha2_simple import *
from thashx8 import *

#include "utils.h"
#include "params.h"
#include "hash.h"
#include "thash.h"
#include "address.h"

def ull_to_bytes(out, outlen, in_):
    """
    Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
    :param out: output
    :param outlen: output length
    :param in_: input
    :return: converted value
    """
    for i in range(outlen-1, -1, -1):
        out[i] = in_ & 0xff
        in_ = in_ >> 8
    return out

def u32_to_bytes(out, in_):
    """
    Converts the inlen bytes in 'in' from big-endian byte order to an integer.
    :param out: output
    :param in_: input
    :return: converted value
    """
    out[0] = (in_ >> 24) & 0xff
    out[1] = (in_ >> 16) & 0xff
    out[2] = (in_ >> 8) & 0xff
    out[3] = in_ & 0xff
    return out

def bytes_to_ull(in_, inlen):
    """
    Converts the inlen bytes in 'in' from big-endian byte order to an integer.
    :param in_: input
    :param inlen: input length
    :return: converted value
    """
    retval = 0
    for i in range(inlen):
        retval |= (in_[i] << (8*(inlen - 1 - i)))
    return retval

def compute_root(root, leaf, leaf_id, id_offset, auth_path, tree_height, ctx, addr):
    """
    Computes a root node given a leaf and an authentication path.
    Expects address to be complete other than the tree_height and tree_index.
    :param root:
    :param leaf:
    :param leaf_id:
    :param id_offset:
    :param auth_path:
    :param tree_height:
    :param ctx:
    :param addr:
    :return:
    """
    buffer = bytearray(2 * SPX_N)

    # if leaf_idx is odd (last bit = 1), current path element is a right child
    # and auth_path has to go left. Otherwise it is the other way around.
    if leaf_id & 1:
        buffer[SPX_N:] = leaf
        buffer[:SPX_N] = auth_path
    else:
        buffer[:SPX_N] = leaf
        buffer[SPX_N:] = auth_path

    auth_path += SPX_N

    for i in range(tree_height - 1):
        leaf_id >>= 1
        id_offset >>= 1
        # Set the address of the node we're creating.
        set_tree_height(addr, i + 1)
        set_tree_index(addr, leaf_id + id_offset)

        # Pick the right or left neighbor, depending on parity of the node.
        if leaf_id & 1:
            thash(buffer + SPX_N, buffer, 2, ctx, addr)
            buffer[:SPX_N] = auth_path
        else:
            thash(buffer, buffer, 2, ctx, addr)
            buffer[SPX_N:] = auth_path
        auth_path += SPX_N

    # The last iteration is exceptional; we do not copy an auth_path node.
    leaf_id >>= 1
    id_offset >>= 1
    set_tree_height(addr, tree_height)
    set_tree_index(addr, leaf_id + id_offset)
    thash(root, buffer, 2, ctx, addr)
    return root

def gen_leaf_wots(leaf, sk_seed, pub_seed, addr):
def treehash(root, auth_path, ctx, leaf_id, id_offset, tree_height):
    """
    For a given leaf index, computes the authentication path and the resulting
    root node using Merkle's TreeHash algorithm.
    Expects the layer and tree parts of the tree_addr to be set, as well as the
    tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
    Applies the offset idx_offset to indices before building addresses, so that
    it is possible to continue counting indices across trees.
    :param root: root of the tree
    :param auth_path: authentication path (addresses?)
    :param ctx: context information
    :param leaf_id: leaf index
    :param id_offset: offset
    :param tree_height: height of the tree
    :return:
    """
    stack = bytearray((tree_height + 1) * SPX_N)
    heights = bytearray(tree_height + 1)
    offset = 0
    idx = 0
    tree_idx = 0

    for idx in range(1 << tree_height):
        # Add the next leaf node to the stack.
        gen_leaf(stack[offset*SPX_N:], ctx, idx + id_offset, tree_addr)
        offset += 1
        heights[offset - 1] = 0

        # If this is a node we need for the auth path..
        if (leaf_id ^ 0x1) == idx:
            auth_path[:] = stack[(offset - 1)*SPX_N:(offset - 1)*SPX_N + SPX_N]

        # While the top-most nodes are of equal height..
        while offset >= 2 and heights[offset - 1] == heights[offset - 2]:
            # Compute index of the new node, in the next layer.
            tree_idx = (idx >> (heights[offset - 1] + 1))

            # Set the address of the node we're creating.
            set_tree_height(tree_addr, heights[offset - 1] + 1)
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (heights[offset-1] + 1)))
            # Hash the top-most nodes from the stack together.
            thash(stack[(offset - 2)*SPX_N:],
                  stack[(offset - 2)*SPX_N:], 2, ctx, tree_addr)
            offset -= 1
            # Note that the top-most node is now one layer higher.
            heights[offset - 1] += 1

            # if this is a node we need for the auth path..
            if ((leaf_id >> heights[offset - 1]) ^ 0x1) == tree_idx:
                auth_path[heights[offset - 1]*SPX_N:] = stack[(offset - 1)*SPX_N:(offset - 1)*SPX_N + SPX_N]
    root[:] = stack[:]
    return root


void treehash(unsigned char *root, unsigned char *auth_path, const spx_ctx* ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                 unsigned char* /* leaf */,
                 const spx_ctx* /* ctx */,
                 uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
              uint32_t tree_addr[8])
{
    SPX_VLA(uint8_t, stack, (tree_height+1)*SPX_N);
    SPX_VLA(unsigned int, heights, tree_height+1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset*SPX_N, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*SPX_N, SPX_N);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (heights[offset-1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash(stack + (offset - 2)*SPX_N,
                  stack + (offset - 2)*SPX_N, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*SPX_N,
                       stack + (offset - 1)*SPX_N, SPX_N);
            }
        }
    }
    memcpy(root, stack, SPX_N);
}
