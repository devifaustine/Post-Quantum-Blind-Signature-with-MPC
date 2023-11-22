# This file executes the benchmark for SPHINCS build from MPC using the help of MPyC library
from signmpyc import SPHINCS
import time
from mpyc.runtime import mpc


sphincs = SPHINCS()

# generate public and private key pair
start = time.time()
key = sphincs.keygen()
end = time.time()

elapsed = end - start
print("time taken to generate the key: %d seconds" % elapsed)

for i in range(len(key)):
    print(type(key[i]))

# runs the sign() function using MPC
# maybe comment the time.time() and unnecessary code when using benchmarking tools from python later

def check_type(x):
    """
    checks the type of x, if message return True, else False (for secret key) or raise error for others
    :param x: string
    :return: True/False
    """
    # case x is secret key
    if x[0] == '(' and x[1] == '(':
        return True
    # case x is a message
    elif x[0] == 'b' and ord(x[1]) == 92:
        return False
    raise ValueError("This is neither a message, nor a secret key!")

async def bench(self):
    # run the sign() function build from mpyc and time it

    secfld = mpc.SecFld()

    # wait until all parties (user and signer) starts the mpc
    await mpc.start()

    # accept input from both user and signer
    payload = input('Give your input here: ')

    # TODO: check the input type (message or sk) and use check_type() to determine the secure object
    try:
        if check_type(payload):
            # payload is a secret key
            x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
            x = secfld.array(x)  # secret-shared input bits
        else:
            # payload is a message
            x = 
    except ValueError:
        print("Payload invalid. Try Again!")
        await mpc.shutdown()


    # TODO: process both inputs from parties and sign the message with the sk
    for i in range(len(payloads)):
        print(payloads[i])
    print("There's the payload")

    # TODO: outputs the blind signature before shutting down
    await mpc.shutdown()


# TODO: verifies if the signature is correct and legit
