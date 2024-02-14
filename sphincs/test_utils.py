# test functions in utils

from mpyc.runtime import mpc
import numpy as np
from sphincs import utils

secfld = mpc.SecFld(2)

# test bits_to_bytestring
def test_bits_to_bytestring():
    byte = b"hello"
    string_bit = ''.join(format(ord(i), '08b') for i in str(byte))

    # payload is a list of secure objects containing the elements of
    x = secfld.array(np.array([1, 0, 0, 0, 0, 0, 0, 0]))
    assert utils.bits_to_bytestring(x) == byte

test_bits_to_bytestring()