# This file executes the benchmark for SPHINCS+ build from MPC using the help of MPyC library
from signmpyc import SPHINCS
import time
from mpyc.runtime import mpc
import numpy as np
import random
import string

# TODO: change SPHINCS to SPHINCS+ in implementation!

sphincs = SPHINCS()
# a group field consisting of 2 elements 0 and 1
secfld = mpc.SecFld(2)

# _________________________________________________________________________________________________
# TODO: delete these as it has been moved to gen_keys_bench.py
"""

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))
# Convert the string to bytes
seed_bytes = seed.encode('utf-8')

# generate public and private key pair
start = time.time()
key = sphincs.keygen(seed_bytes)
end = time.time()

print(key)

elapsed = end - start
print("time taken to generate the key: %d seconds" % elapsed)

print("sk =", key[1])

"""
# _________________________________________________________________________________________________

# runs the sign() function using MPC
# maybe comment the time.time() and unnecessary code when using benchmarking tools from python later

def q_split(q):
    """
    function to parse q in form of string
    :param q: Q in SK
    :return: Q in its original form a list of bytestring
    """
    #TODO: fix this function!
    res = []
    for i in range(len(q)):
        if i == 0:  # [ present at the first char
            res.append(eval(q[i][1:]))
            print(res[i])
        elif i == len(q) - 1:
            res.append(eval(q[i][:-1]))
        else:
            res.append(eval(q[i]))
    return res


def split_sk(sk):
    """
    sk includes pk and the real secret key SK = (PK, (SK1, SK2, Q))
    :param sk: secret key
    :return: (pk, (sk1, sk2, q))
    """
    #TODO: fix this function!
    pk, sk_eval = eval(sk)

    sk1 = eval(sk_eval[0])  # Using eval to convert the string back to bytes
    sk2 = eval(sk_eval[1])
    q_str = sk_eval[2:]
    q = q_split(q_str)

    return pk, (sk1, sk2, q)

def check_type(x):
    """
    checks the type of x, if message return True, else False (for secret key) or raise error for others
    :param x: string
    :return: True/False
    """
    # case x is secret key
    if x[0] == '(' and x[1] == "b" and x[-1] == ")":
        if isinstance(eval(x), tuple):
            return True
        else: return False
    # case x is a message, messages always starts with 'b/'
    # elif x[0] == 'b' and ord(x[1]) == 92:
    else:
        return False
    # TODO: raise ValueError("This is neither a message, nor a secret key!")

# note: first party (with index = 0) is always the user
# and second party (index = 1) is always the signer for simplicity
# this can be changed and can be checked before the signing function is executed

# run the sign() function build from mpyc and time it
async def main():

    # wait until all parties starts the mpc and joins
    await mpc.start()

    len_parties = len(mpc.__getattribute__("parties"))

    # number of parties needs to be exactly 2 (user and signer)
    if len_parties < 2 or len_parties > 2:
        raise AttributeError("The number of parties needs to be exactly 2!")

    # accept input from both user and signer
    payload = input('Give your input here: ')
    print("here's your payload: ", payload)

    # payload is of type string (str)

    # TODO: find out if secfld can be used as np.array results in error

    # check the type of payload (either message or secret key) and convert it to secure object
    try:
        if check_type(payload):
            print("The given input is a secret key!")
            # payload is a secret key
            sk1, sk2, q = split_sk(payload)
            sk = (sk1, sk2, q)
            # TODO: convert each element of sk into secure obj (SecFld and array)
            # TODO: new! overwrite payload with secure object (to be transfered with mpc.input())
            sk1_bit = np.array([(b >> 1) & 1 for b in sk1 for i in range(8)])
            #x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
            #x = secfld.array(x)      # secret-shared input bits
        else:
            print("The given input is a message!")
            # payload is a message
            # TODO: new! overwrite payload with secure object (to be transfered with mpc.input())
            m = payload # TODO: but as secure object of type SecFld array of bytes

    except ValueError:
        print("Payload invalid. check_type failed to recognize the pattern. Try Again!")
        await mpc.shutdown()

    # both parties share their inputs using mpc.input() - Shamir's Secret Sharing Scheme
    inputs = mpc.input(payload)

    # inputs[0] = message
    # inputs[1] = secret key
    # both of type secure objects

    print()
    print("Signing process begins now...")

    sig = sphincs.sign(inputs[0], inputs[1])

    print("Signature generated!\nHere is the signature: ", await mpc.output(sig))

    # TODO: assert verify the signature before shutting down

    await mpc.shutdown()

if __name__ == "__main__":
    mpc.run(main())