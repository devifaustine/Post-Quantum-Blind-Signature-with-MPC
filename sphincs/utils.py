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
        # x should be of type string
        bits = ''.join(format(ord(i), '08b') for i in str(x))
        bitlist = [int(i) for i in bits]
        return self.secfld.array(np.array(bitlist))

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

