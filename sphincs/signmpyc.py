from mpyc.runtime import mpc
from sha3 import sha3, shake
import pyspx.shake_256f


def check_type(x):
    """
    checks the type of x and returns the secure type of itself
    :return: secure x
    """
    return mpc.SecInt(32)

async def main():
    secint = mpc.SecInt(16)

    await mpc.start()

    payload = input('Give your input here: ')

    payloads = mpc.input(secint(payload))

    for i in range(len(payloads)):
        print(payloads[i])
    print("There's the payload")

    await mpc.shutdown()

mpc.run(main())
