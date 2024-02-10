# this class contains utilities for the sphincs+ library
import mpyc.runtime as mpc
import numpy as np

secfld = mpc.SecFld(2)

def to_secarray(x):
    """
    converts the input to a secure field
    :param x: input (typically string)
    :return: binary representation of type secure array in SecFld(2)
    """
    # x should be of type string
    bits = ''.join(format(ord(i), '08b') for i in str(x))
    bitlist = [int(i) for i in bits]
    return secfld.array(np.array(bitlist))

async def bits_to_string(x):
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