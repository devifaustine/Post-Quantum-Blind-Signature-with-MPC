# This file executes the benchmark for SPHINCS+ build from MPC using the help of MPyC library
from signmpyc import SPHINCS
from mpyc.runtime import mpc
import numpy as np
import binascii
import time

sphincs = SPHINCS()
# a group field consisting of 2 elements 0 and 1
secfld = mpc.SecFld(2)

# set log to True to print the output
log = True

def xprint(s, d=''):
    """
    function to print the output if global variable log is set to True
    :param s: string
    :param d: optional string
    :return: none
    """
    if log:
        print(s)

def split_sk(key):
    """
    sk includes pk and the real secret key SK = (PK, (SK1, SK2, Q))
    :param key: public and private key pair in form (pk, sk1 || sk2 || pk || q)
    :return: (sk.seed, sk.prf, pk.seed, pk.root) each of length
    """
    # every element has length 32 bytes
    key_fixed = key.replace("x", '\\x')
    pk, sk_eval = eval(key_fixed)

    sk_seed = sk_eval[:32]
    sk_prf = sk_eval[32:64]
    pk_seed = sk_eval[64:96]
    pk_root = sk_eval[96:]

    # inputs from bash script eliminates '\' in pk_root, so we have to fix it
    assert len(sk_prf) == len(sk_seed) == len(pk_seed) == len(pk_root) == 32
    return sk_seed, sk_prf, pk_seed, pk_root

# _________________________________________________________________________________________________

# runs the sign() function using MPC
# maybe comment the time.time() and unnecessary code when using benchmarking tools from python later


def to_bytes(y):
    """
    converts y in binary to bytes
    :param y: list/array of bits
    :return: byte representation of y
    """
    x_bitstring = ''.join(str(bit) for bit in y)

    # Convert the binary string back to bytes
    x_bytes = bytes(int(x_bitstring[i:i + 8], 2) for i in range(0, len(x_bitstring), 8))

    return eval(x_bytes)

def check_length(x):
    """
    checks the length of list x, if each is not of length 256, pad this with leading zeros
    :param x: list of binary representation of elements of secret key
    :return: list of binary representation of elements of secret key
    """
    if type(x) != list:
        x = [x]
    for i in range(len(x)):
        if len(x[i]) < 256:
            x[i] = '0' * (256 - len(x[i])) + x[i]
    return x

def check_type(x):
    """
    checks the type of x, if message return True, else False (for secret key) or raise error for others
    :param x: string
    :return: True/False
    """
    # case x is secret key
    if x[0] == '(' and x[1] == "b" and x[-1] == ")":
        if x.__contains__(','):
            return True
        else:
            raise ValueError("Invalid secret key format!")
    # case x is a message, messages always starts with 'b/'
    # elif x[0] == 'b' and ord(x[1]) == 92:
    else:
        return False

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
    in_ = input('Give your input here: ')
    print("here's your payload: ", in_)

    # payload is of type string (str)
    # TODO: remember to pad the message as it is not of length n (?) do we need to pad here or in signmpyc? - check

    payload = None

    # check the type of payload (either message or secret key) and convert it to secure objects
    try:
        if check_type(in_):
            xprint("The given input is a secret key!")
            # payload is a secret key
            # split the sk into its elements
            sk_seed, sk_prf, pk_seed, pk_root = split_sk(in_)
            pkseed_bit = bin(int.from_bytes(pk_seed, byteorder='big')).replace("0b", "")
            pkroot_bit = bin(int.from_bytes(pk_root, byteorder='big')).replace("0b", "")
            skseed_bit = bin(int.from_bytes(sk_seed, byteorder='big')).replace("0b", "")
            skprf_bit = bin(int.from_bytes(sk_prf, byteorder='big')).replace("0b", "")

            # check bit lengths, should be 256 each?
            key_ele_bit = check_length([skprf_bit, skseed_bit, pkseed_bit, pkroot_bit])

            payload = []

            # payload is a list of secure objects containing the elements of sk
            for i in key_ele_bit:
                payload.append(secfld.array(np.array([int(j) for j in i])))

        else:
            xprint("The given input is a message!")
            # payload is a message
            mes_bit = ''.join(format(ord(i), '08b') for i in in_)
            # payload is a list and the first element is the message, the rest is just an empty array - unused
            payload = [secfld.array(np.array([int(i) for i in mes_bit])),
                       secfld.array(np.array([])),
                       secfld.array(np.array([])),
                       secfld.array(np.array([]))]      # secret-shared input message bits in list
    except ValueError:
        print("Payload invalid. check_type failed to recognize the pattern. Try Again!")
        await mpc.shutdown()

    # both parties share their inputs using mpc.input() - Shamir's Secret Sharing Scheme
    inputs = mpc.input(payload)
    my_payload = None


    print("here's the payload: ", payload)
    print("here's the inputs: ", inputs)

    # TODO: test why output does not work here - try outputting here to check verification
    #  process to get original values of pk - this works for the instance that give the input/payload first.
    #  the other instance will crash and not be able to output their payload. - find out why

    print("here's the pk_seed: ", await mpc.output(payload[2]))
    print("here's the pk_root: ", await mpc.output(payload[3]))
    print("here's the sk_seed: ", await mpc.output(payload[0]))
    print("here's the sk_prf: ", await mpc.output(payload[1]))

    for i in payload:
        print("payload: ", i)
        print("check: ", await mpc.output(i))

    # inputs[0][0] = message
    # inputs[1] = list of elements of the secret key
    # both of type secure objects

    print()
    print("Signing process begins now...")

    # initializing variables for time
    start = None
    end = None

    # catch exceptions in case of errors
    try:
        start = time.time()
        sig = await sphincs.sign(inputs[0][0], inputs[1])
        end = time.time()
    except (NotImplementedError, AttributeError, ValueError, RuntimeError):
        print("Error during signing process. Try Again!")
        await mpc.shutdown()

    print("Signature generated!\nHere is the signature: ", await mpc.output(sig))
    end_out = time.time()
    elapsed1 = end - start  # elapsed time until sign() is done
    elapsed2 = end_out - start  # elapsed time until output is printed

    # write the elapsed time to bench_res.txt
    with open("bench_res.txt", "w") as file:
        var = str(elapsed1) + " " + str(elapsed2) + '\n'
        file.write(var)

    # TODO: assert verify the signature before shutting down
    # verify() accepts the signature, message and public key as bytes not SecObj
    # TODO: convert pkseed and pkroot to bytes (use function in utils)
    pkseed = inputs[1][2]
    pkroot = inputs[1][3]
    pk = pkseed + pkroot # public key in bytes
    assert await sphincs.verify(sig, inputs[0][0], pk)

    await mpc.shutdown()

if __name__ == "__main__":
    mpc.run(main())