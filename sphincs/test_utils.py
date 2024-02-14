# test functions in utils

from mpyc.runtime import mpc
import numpy as np
from utils import UTILS

# initialize the utilities class and secure field s
util = UTILS()
secfld = mpc.SecFld(2)


async def bits_to_bytestring(y):
    """
    converts x from array of bits of secure object to normal bytes
    :param x: input of type secfld.array (secure array)
    :return: bytes(x)
    """
    x = await mpc.output(y)
    x_bitstring = ''.join(str(bit) for bit in x)

    # Convert the binary string back to bytes
    x_bytes = bytes(int(x_bitstring[i:i + 8], 2) for i in range(0, len(x_bitstring), 8))

    return eval(x_bytes)

# test bits_to_bytestring
async def test_bits_to_bytestring(byte = b"hello"):
    await mpc.start()
    string_bit = ''.join(format(ord(i), '08b') for i in str(byte))

    # payload is a list of secure objects containing the elements of
    x = secfld.array(np.array([int(i) for i in string_bit]))
    print("original byte: ", byte)

    converted_byte = mpc.convert()
    print(converted_byte)

    #convert the bits to bytes
    x = await mpc.output(x)
    x_bitstring = ''.join(str(bit) for bit in x)

    # Convert the binary string back to bytes
    x_bytes = bytes(int(x_bitstring[i:i + 8], 2) for i in range(0, len(x_bitstring), 8))


    out = await mpc.output(x_bytes)

    print("converted byte: ", out)
    assert out == byte
    await mpc.shutdown()

async def main():
    await mpc.start()

    await test_bits_to_bytestring(b'hello')

    await mpc.shutdown()

mpc.run(main())