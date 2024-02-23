# benchmark the hash generation of shake256 with secure object

from shake import SHAKE
from mpyc.runtime import mpc
from time import *
import random
import string
from utils import UTILS
import numpy as np

util = UTILS()
shake = SHAKE() # create a shake object
secfld = mpc.SecFld(2)

# number of times
n = 100

def gen_mes(n: int, length: int):
    """
    generats a list of n messages of type string
    :param n: number of messages
    :param length: max length of each message
    :return: list of messages
    """
    chars = string.ascii_letters + string.digits
    res = []
    for i in range(n):
        mes = ''.join(random.choice(chars) for _ in range(n))
        res.append(mes)
    return res

# generate n messages
messages = gen_mes(n, 70)

# benchmark the hash generation of shake256 with secure object
for i in range(len(messages)):
    mes = util.to_secarray(messages[i])
    start = time()
    hash = shake.shake(mes, 256, 512)
    end = time()
    print("Time elapsed for message %d: %f" %(i, end - start))

