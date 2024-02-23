# tests the secure array in mpyc

from mpyc.runtime import mpc
import numpy as np
from math import log

secfld = mpc.SecFld(2)  # bits

async def test_split_array():
    await mpc.start()

    # create a secure array
    array = np.array([1, 2, 3, 4, 5, 6, 7, 8])
    a = secfld.array(array)

    # split the array
    b = mpc.np_split(a, 2)

    # np_split splits the array equally into y parts

    print("here's the original array: ", await mpc.output(a))
    print("here's the array split into: ", await mpc.output(b))

    await mpc.shutdown()

async def test_first_x_bits():
    await mpc.start()

    # create secure array
    array = np.array([1, 2, 3, 4, 5, 6, 7, 8])
    a = secfld.array(array)

    b = None
    stype = type(a)
    for i in a:
        print(i)
        b = [stype(r) for r in a]

    print("Here's the original array: ", await mpc.output(a))
    print("Here's the first 3 bits of the array: ", await mpc.output(mpc.convert(b, secfld)))

    await mpc.shutdown()

def base_w(x, w, out_len):
    """
    converts an integer to base w
    :param x: integer
    :param w: winternitz parameter
    :param out_len: output length
    :return: out_len int array basew
    """
    # TODO: check this function and implement it
    in_ = 0
    out_ = 0
    total = 0
    bits = 0
    basew = [0] * out_len

    for consumed in range(out_len):
        if bits == 0:
            total = x[in_]
            in_ += 1
            bits += 8
        bits -= int(log(w, 2))
        basew[out_] = (total >> bits) & (w - 1)
        out_ += 1
    return basew

def test_basew():
    x = b'hello'
    w = 16
    out_len = 4
    print(base_w(x, w, out_len))

test_basew()
mpc.run(test_first_x_bits())
mpc.run(test_split_array())
