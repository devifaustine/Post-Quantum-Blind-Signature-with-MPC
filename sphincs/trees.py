from math import log2, ceil

def hash_tree(h, leaves):
    """
    generate hash tree for the
    :param h: height/hash function
    :param leaves: list of nodes for the leaves
    :return: binary tree
    """
    assert (len(leaves) & len(leaves) - 1) == 0 # test fpr full binary tree
    return l_tree(h, leaves) # binary hash trees are special cases of L-Trees

def l_tree(h, leaves):
    """
    outputs a binary tree from leaves
    :param h: height function
    :param leaves: list of nodes
    :return: layers for the binary tree
    """
    layer = leaves
    yield layer
    for i in range(ceil(log2(len(leaves)))):
        next_layer = [h(l, r, i) for l, r in zip(layer[0::2], layer[1::2])]
        if len(layer) & 1: # if there is a node left on this layer
            next_layer.append(layer[-1])
        layer = next_layer
        yield layer

def auth_path(tree, id):
    """
    generates path for the tree to a specific id in the tree.
    The authentication path includes the nodes that would be needed to verify the integrity of the leaf node's content.
    :param tree: the binary tree
    :param id: index of the element searched
    :return: path to the element with index id
    """
    path = []
    for layer in tree:
        if len(layer) == 1: # there are no neighbors
            break
        id += 1 if (id & 1 == 0) else -1 # neighbor node
        path.append(layer[id])
        id >>= 1 # parent node
    return path

def construct_root(h, auth_path, leaf, id):
    """
    verifies the integrity of a leaf node within the binary hash tree.
    :param h: height/hash function
    :param auth_path: The authentication path, which is a list of nodes that need
                    to be combined to verify the integrity of the leaf node.
    :param leaf: leaf node
    :param id: the id of the leaf node
    :return: root node of the binary tree
    """
    node = leaf
    for i, neighbor in enumerate(auth_path):
        if id & 1 == 0:
            node = h(node, neighbor, i)
        else:
            node = h(neighbor, node, i)
        id >>= 1
    return node

def root(tree):
    """
    extracts the root of a tree
    :param tree: the (binary) tree
    :return: the root of the tree
    """
    return list(tree)[-1][0]
