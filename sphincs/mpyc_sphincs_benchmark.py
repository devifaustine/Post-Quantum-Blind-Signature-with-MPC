# This file executes the benchmark for SPHINCS build from MPC using the help of MPyC library
from signmpyc import SPHINCS
import time
from mpyc.runtime import mpc
import numpy as np
import random
import string

# TODO: change SPHINCS to SPHINCS+ in implementation!

sphincs = SPHINCS()
secfld = mpc.SecFld(2)

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

# runs the sign() function using MPC
# maybe comment the time.time() and unnecessary code when using benchmarking tools from python later

def q_split(q):
    """
    function to parse q in form of string
    :param q: Q in SK
    :return: Q in its original form a list of bytestring
    """
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
    split secret key sk (type = bytestring) into its components of type tuple
    :param sk: secret key
    :return: (sk1, sk2, q)
    """
    sk = sk.strip("()")  # Remove parentheses
    sk_split_str = sk.split(", ")

    sk1 = eval(sk_split_str[0])  # Using eval to convert the string back to bytes
    sk2 = eval(sk_split_str[1])
    q_str = sk_split_str[2:]
    q = q_split(q_str)

    return sk1, sk2, q

def check_type(x):
    """
    checks the type of x, if message return True, else False (for secret key) or raise error for others
    :param x: string
    :return: True/False
    """
    # case x is secret key
    if x[0] == 'b' and x[1] == "'" and x[-1] == "'":
        return True
    # case x is a message, messages always starts with 'b/'
    # elif x[0] == 'b' and ord(x[1]) == 92:
    else:
        return False
    # TODO: raise ValueError("This is neither a message, nor a secret key!")

async def main():
    # run the sign() function build from mpyc and time it

    secfld = mpc.SecFld()

    # wait until all parties (user and signer) starts the mpc
    await mpc.start()

    # accept input from both user and signer
    payload = input('Give your input here: ')

    print("type of payload is: ", type(payload))
    print("you entered: ", payload)

    print(check_type(payload))

    try:
        if check_type(payload):
            # payload is a secret key
            sk1, sk2, q = split_sk(payload)
            sk = (sk1, sk2, q)
            await mpc.transfer("signer has given their input")
            # TODO:  convert each element of sk into secure obj (SecFld and array)
            sk1_bit = np.array([(b >> 1) & 1 for b in sk1 for i in range(8)])
            #x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
            #x = secfld.array(x)  # secret-shared input bits
        else:
            # payload is a message
            m = payload # TODO: but as secure object of type SecFld array of bytes

            await mpc.transfer("user has given their input")
    except ValueError:
        print("Payload invalid. check_type failed to recognize the pattern. Try Again!")
        await mpc.shutdown()

    print()
    await mpc.transfer("Signing process begins now...")

    sig = sphincs.sign(m, sk)

    print("Here is the signature desired: ", sig)

    await mpc.shutdown()

if __name__ == "__main__":
    mpc.run(main())