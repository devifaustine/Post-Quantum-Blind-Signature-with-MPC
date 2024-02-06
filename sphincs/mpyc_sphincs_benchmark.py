# This file executes the benchmark for SPHINCS+ build from MPC using the help of MPyC library
from signmpyc import SPHINCS
from mpyc.runtime import mpc
import numpy as np

sphincs = SPHINCS()
# a group field consisting of 2 elements 0 and 1
secfld = mpc.SecFld(2)

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
    # TODO: remember to pad the payload

    # check the type of payload (either message or secret key) and convert it to secure objects
    try:
        if check_type(payload):
            print("The given input is a secret key!")
            # payload is a secret key
            # split function need to be done in signmpyc.py
            sk_bit = ''.join(format(ord(i), '08b') for i in payload)
            payload = [int(i) for i in sk_bit]      # secret-shared input sk bits in list
        else:
            print("The given input is a message!")
            # payload is a message
            mes_bit = ''.join(format(ord(i), '08b') for i in payload)
            payload = [int(i) for i in mes_bit]      # secret-shared input message bits in list
    except ValueError:
        print("Payload invalid. check_type failed to recognize the pattern. Try Again!")
        await mpc.shutdown()

    # both parties share their inputs using mpc.input() - Shamir's Secret Sharing Scheme
    inputs = mpc.input(secfld.array(np.array(payload)))

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

    await mpc.shutdown()

if __name__ == "__main__":
    mpc.run(main())