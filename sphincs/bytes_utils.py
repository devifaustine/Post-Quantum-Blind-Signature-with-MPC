def xor(b1, b2):
    """
    returns xor of b1 and b2
    :param b1: byte object of length n
    :param b2: byte object of length n
    :return: b1 xor b2
    """
    assert len(b1) == len(b2)
    return bytes([x ^ y for x, y in zip(b1, b2)])


def chunkbytes(a, n):
    """
    splits a string into smaller chunks each of size n
    :param a: string
    :param n: positive integer
    :return: a list of these chunks
    """
    return [a[i:i+n] for i in range(0, len(a), n)]


def ints_from_4bytes(a):
    """
    returns the integer value of a (of type bytes size 4)
    :param a: byte
    :return: integer
    """
    for chunk in chunkbytes(a, 4):
        yield int.from_bytes(chunk, byteorder='little')


def ints_to_4bytes(x):
    """
    returns a 4-sized byte representation of integer x
    :param x: integer
    :return: a byte size 4
    """
    for v in x:
        yield int.to_bytes(v, length=4, byteorder='little')
