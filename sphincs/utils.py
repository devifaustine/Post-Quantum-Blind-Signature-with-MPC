# this class contains utilities for the sphincs+ library
from mpyc.runtime import mpc
import numpy as np

class UTILS(object):
    def __init__(self):
        self.byte = 2
        self.int_ = 16
        self.secfld = mpc.SecFld(self.byte)

    def to_secarray(self, x):
        """
        converts the input to a secure field
        :param x: input (typically string)
        :return: binary representation of type secure array in SecFld(2)
        """
        if isinstance(x, str):
            # convert x to bytes
            x = x.encode('utf-8')
        x_bits = bin(int.from_bytes(x, byteorder='big')).replace("0b", "")
        return self.secfld.array(np.array([int(i) for i in x_bits]))

    async def bits_to_bytestring(self, y):
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

    def toByte(self, x, y):
        """
        returns a y-byte string containing binary representation of x in big endian order
        :param x: non-negative integer
        :param y: non-negative integer
        :return: bytestring of length y
        """
        return x.to_bytes(y, byteorder='big')

    async def bits_to_string(self, x):
        """
        converts x from array of bits of secure object to a normal string
        :param x: input of type secfld.array (secure array)
        :return: str(x)
        """
        i = 0
        j = 1
        # TODO - implement the function
        # check for loop for every 8 bits (1 byte = 8 bits) so i is lower counter and j is upper counter
        for a in x:
            # TODO: implement here
            break
        return None

