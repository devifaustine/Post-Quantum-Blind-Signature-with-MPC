# This file executes the benchmark for SPHINCS+ build from MPC using the help of MPyC library
from signmpyc import SPHINCS
from mpyc.runtime import mpc
import numpy as np
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

def get_pk(key):
    """
    get the public key from the secret key
    :param key: secret key
    :return: public key
    """
    key_s = key.replace("x", '\\x')
    pk, sk = eval(key_s)
    return pk

def split_sk(key):
    """
    sk includes pk and the real secret key SK = (PK, (SK1, SK2, Q))
    :param key: public and private key pair in form (pk, sk1 || sk2 || pk || q)
    :return: (sk.seed, sk.prf, pk.seed, pk.root) each of length
    """
    # every element has length 32 bytes
    key_fixed = key.replace("x", '\\x')
    key_fixed = key_fixed.replace("r", '\\r')
    key_fixed = key_fixed.replace("n", '\\n')
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

def pad(x, y):
    """
    pad the array x with zeroes until y length is reached
    :param x: to be padded
    :param y: length to be reached
    :return: new array of length y
    """
    pass

def check_length(x, y):
    """
    checks the length of list x, if each is not of length 256, pad this with leading zeros
    :param x: binary representation of type string
    :param y: desired length
    :return: padded string
    """
    res = ""
    if len(x) < y:
        res += ((y - len(x)) * "0")  # pad with leading 0s
    res += x
    return res

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
    sig = None
    len_parties = len(mpc.__getattribute__("parties"))

    # number of parties needs to be exactly 2 (user and signer)
    assert len_parties == 2, "The number of parties needs to be exactly 2!"

    # accept input from both user and signer
    in_ = input('Give your input here: ')
    print("here's your payload: ", in_)

    # payload is of type string (str)
    # TODO: remember to pad the message as it is not of length n (?) do we need to pad here or in signmpyc? - check

    payload = None
    mes = None
    sk = None
    pk_seed = None
    pk_root = None
    sk_seed = None
    sk_prf = None

    # check the type of payload (either message or secret key) and convert it to secure objects
    try:
        if check_type(in_):
            xprint("The given input is a secret key!")
            # payload is a secret key
            # split the sk into its elements
            try:
                sk_seed, sk_prf, pk_seed, pk_root = split_sk(in_)
            except SyntaxError:
                print("Secret key value generated is wrong. Please restart the function and try again!")
                await mpc.shutdown()
            pkseed_bit = bin(int.from_bytes(pk_seed, byteorder='big')).replace("0b", "")
            pkroot_bit = bin(int.from_bytes(pk_root, byteorder='big')).replace("0b", "")
            skseed_bit = bin(int.from_bytes(sk_seed, byteorder='big')).replace("0b", "")
            skprf_bit = bin(int.from_bytes(sk_prf, byteorder='big')).replace("0b", "")

            sk_ele_bit = [skseed_bit, skprf_bit, pkseed_bit, pkroot_bit]

            # check bit lengths, should be 256 each?
            for i in range(len(sk_ele_bit)):
                sk_ele_bit[i] = check_length(sk_ele_bit[i], 256)

            payload = [secfld.array(np.array([int(i) for i in sk_ele_bit[0]])),
                        secfld.array(np.array([int(i) for i in sk_ele_bit[1]])),
                        secfld.array(np.array([int(i) for i in sk_ele_bit[2]])),
                        secfld.array(np.array([int(i) for i in sk_ele_bit[3]]))]

            mes = input('Give the other input here: ')
            sk = in_

        else:
            xprint("The given input is a message!")
            # payload is a message
            mes_bit = ''.join(format(ord(i), '08b') for i in in_)

            # check if mes_bit is of length 256, if not pad with 0s
            mes_bit = check_length(mes_bit, 256)

            # payload is a list and the first element is the message, the rest is just an empty array - unused
            payload = [secfld.array(np.array([int(i) for i in mes_bit])),
                       secfld.array(np.array([])),
                       secfld.array(np.array([])),
                       secfld.array(np.array([]))]      # secret-shared input message bits in list
            mes = in_
            sk = input('Give the other input here: ')
    except TypeError: 
        print("Something went wrong in splitting the sk. Try Again!")
        await mpc.shutdown()
        return
    except ValueError:
        print("Payload invalid. check_type failed to recognize the pattern. Try Again!")
        await mpc.shutdown()
        return

    # both parties share their inputs using mpc.input() - Shamir's Secret Sharing Scheme
    inputs = mpc.input(payload)
    my_payload = None

    print("here's the payload: ", payload)
    print("here's the inputs: ", inputs)

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
        sig = await sphincs.sign(inputs[0][0], inputs[1], mes, sk)
        end = time.time()
    except AssertionError:
        print("The length of the message and secret key is wrong! Please restart the function!")
        await mpc.shutdown()
        #return
    except SyntaxError:
        print("Secret key value generated is wrong. Please restart the function and try again!")
        await mpc.shutdown()
        #return
    except (NotImplementedError, AttributeError, ValueError, RuntimeError):
        print("Error during signing process. Try Again!")
        await mpc.shutdown()
        #return 

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

    pk = get_pk(sk)  # public key in bytes
    assert sphincs.verify(sig, mes, pk)

    await mpc.shutdown()

mpc.run(main())
