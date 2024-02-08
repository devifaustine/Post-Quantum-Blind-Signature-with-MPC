# This file executes the benchmark for SPHINCS+ build from MPC using the help of MPyC library
from signmpyc import SPHINCS
from mpyc.runtime import mpc
import numpy as np

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
    pk, sk_eval = eval(key)

    sk_seed = sk_eval[:32]
    sk_prf = sk_eval[32:64]
    pk_seed = sk_eval[64:96]
    pk_root = sk_eval[96:]
    #pk_root = sk_eval[96:128]
    # TODO: is q a padding?
    #q = sk_eval[128:]
    return sk_seed, sk_prf, pk_seed, pk_root #, q

# _________________________________________________________________________________________________

# runs the sign() function using MPC
# maybe comment the time.time() and unnecessary code when using benchmarking tools from python later

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
    # TODO: remember to pad the payload

    payload = None

    # check the type of payload (either message or secret key) and convert it to secure objects
    try:
        if check_type(in_):
            xprint("The given input is a secret key!")
            # payload is a secret key
            # split the sk into its elements
            sk_seed, sk_prf, pk_seed, pk_root, q = split_sk(in_)
            pkseed_bit = ''.join(format(ord(i), '08b') for i in str(pk_seed))
            pkroot_bit = ''.join(format(ord(i), '08b') for i in str(pk_root))
            skseed_bit = ''.join(format(ord(i), '08b') for i in str(sk_seed))
            skprf_bit = ''.join(format(ord(i), '08b') for i in str(sk_prf))
            #q_bit = ''.join(format(ord(i), '08b') for i in str(q))

            # payload is a list of secure objects containing the elements of sk
            payload = [secfld.array(np.array([int(i) for i in skseed_bit])),
                       secfld.array(np.array([int(i) for i in skprf_bit])),
                       secfld.array(np.array([int(i) for i in pkseed_bit])),
                       secfld.array(np.array([int(i) for i in pkroot_bit]))]
        else:
            xprint("The given input is a message!")
            # payload is a message
            mes_bit = ''.join(format(ord(i), '08b') for i in in_)
            payload = secfld.array(np.array([int(i) for i in mes_bit]))      # secret-shared input message bits in list
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

    # catch exceptions in case of errors
    try:
        sig = sphincs.sign(inputs[0], inputs[1])
    except (NotImplementedError, AttributeError):
        print("Error during signing process. Try Again!")
        await mpc.shutdown()

    print("Signature generated!\nHere is the signature: ", await mpc.output(sig))

    # TODO: assert verify the signature before shutting down
    # TODO: inputs[0] and inputs[1] needs to be bytes and not secure objects
    assert await sphincs.verify(sig, inputs[0], inputs[1])

    await mpc.shutdown()

if __name__ == "__main__":
    mpc.run(main())