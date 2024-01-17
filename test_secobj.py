# test secure object in MPyC
import numpy as np
from mpyc.runtime import mpc
from mpyc.gfpx import GFpX
from hashlib import sha3_224, sha3_256, sha3_384, sha3_512

# variables for main5()
secfld = mpc.SecFld(2)
triangular_numbers = tuple(i*(i+1)//2 % 64 for i in range(1, 25))

round_constants = tuple(tuple(int(GFpX(2).powmod('x', 7*i + j, 'x^8+x^6+x^5+x^4+1')) % 2
                              for j in range(7))
                        for i in range(24))

async def xprint(text, s):
    """Print and return bit array s as hex string."""
    s = await mpc.output(s)
    s = np.fliplr(s.reshape(-1, 8)).reshape(-1)  # reverse bits for each byte
    d = len(s)
    s = f'{int("".join(str(int(b)) for b in s), 2):0{d//4}x}'  # bits to hex digits with leading 0s
    print(f'{text} {s}')
    return s

async def main():
    secint = mpc.SecInt(16)

    await mpc.start()

    my_age = int(input("Enter your age: "))
    # my_age divided into shares and distributed among all parties
    # result (our_ages) also contain other parties' shares
    our_ages = mpc.input(secint(my_age))

    # wait for 10 seconds
    #await asyncio.sleep(10)

    print(our_ages)
    for age in our_ages:
        print(age.share)

    total_age = sum(our_ages)
    max_age = mpc.max(our_ages)
    m = len(mpc.parties)
    above_avg = mpc.sum(age * m > total_age for age in our_ages)

    print("Average age: ", await mpc.output(total_age) / m)
    print("Maximum age: ", await mpc.output(max_age))
    print("Number of elderly: ", await mpc.output(above_avg))

    await mpc.shutdown()

# test sum of ages for 3 parties
async def main2():
    secint = mpc.SecInt(16)

    await mpc.start()

    my_age = int(input("Enter your age: "))

    ages = mpc.input(secint(my_age))

    added = mpc.add(ages[0], ages[1])
    added2 = mpc.add(ages[1], ages[2])
    total = mpc.add(ages[0], mpc.add(ages[1], ages[2]))
    print("Sum of our age 1 and age 2 is: ", await mpc.output(added))
    print("Sum of our age 2 and age 3 is: ", await mpc.output(added2))
    print("Your total age is: ", await mpc.output(total))
    await mpc.shutdown()

# test subtraction of 2 numbers for (the first) 2 parties
# index of ages represent -I in the command line (not from who is the first to give the input)
async def main3():
    secint = mpc.SecInt(16)

    await mpc.start()

    my_age = int(input("Enter your number: "))

    ages = mpc.input(secint(my_age))

    #tmp = 0
    tmp = mpc.add(ages[0], mpc.neg(ages[1]))
    #tmp = mpc.mul(ages[0], mpc.neg(ages[1]))

    # the below statement does not work because share is still future pending atm
    #tmp = ages[0].share - ages[1].share

    #res = mpc.secint(tmp)
    print("0-1: ", await mpc.output(tmp))
    print("Number 0: ", await mpc.output(ages[0]))
    print("Number 1: ", await mpc.output(ages[1]))

    # why is tmp == -42? because 3 * -14 = -42 = 14 * -3

    await mpc.shutdown()

# check homomorphism
async def main4():
    secint = mpc.SecInt(16)

    await mpc.start()

    in_ = int(input("Enter your number: "))
    inputs = mpc.input(secint(in_))

    # ((3 * i0) + (2 * i1)) / 2

    tmp = mpc.mul(secint(3), inputs[0])
    tmp2 = mpc.mul(secint(2), inputs[1])
    tmp3 = mpc.add(tmp, tmp2)
    res = mpc.div(tmp3, 2)
    # TODO: Code here!

    print("Result: ", await mpc.output(res))
    print("tmp: ", await mpc.output(tmp))
    print("tmp2: ", await mpc.output(tmp2))
    print("tmp3: ", await mpc.output(tmp3))
    print()
    print("Number 0: ", await mpc.output(inputs[0]))
    print("Number 1: ", await mpc.output(inputs[1]))

    await mpc.shutdown()

@mpc.coroutine
async def keccak_f1600(S):
    """Keccak-f[1600] permutation applied to 1600-bit array S.

    Slightly optimized version, operating over finite field arrays.
    """
    await mpc.returnType((type(S), S.shape))
    # Convert S into 3D array A[x, y, z] = S[64(5y + x) + z]
    S = await mpc.gather(S)  # NB: S is now a finite field array
    S = S.copy()  # TODO: investigate why needed for SHAKE with d > r
    A = S.reshape(5, 5, 64).transpose(1, 0, 2)

    for r in range(24):
        # Apply θ
        C = A.sum(axis=1)
        D = np.roll(C, 1, axis=0) + np.roll(np.roll(C, -1, axis=0), 1, axis=1)
        A += D[:, np.newaxis, :]

        # Apply ρ and π
        x, y = 1, 0
        lane = A[x, y]
        for shift in triangular_numbers:
            x, y = y, (2*x + 3*y) % 5
            lane, A[x, y] = A[x, y].copy(), np.roll(lane, shift)

        # Apply χ
        A += (np.roll(A, -1, axis=0) + 1) * np.roll(A, -2, axis=0)
        A = await mpc._reshare(A)

        # Apply ι
        for j in range(7):
            A[0, 0, (1<<j)-1] += round_constants[r][j]

    S = A.transpose(1, 0, 2).reshape(1600)
    return S

def sponge(r, N, d):
    """Sponge construction with the Keccak-f[1600] permutation with rate r and output length d."""
    # Pad with 10^*1 to make input length multiple of r.
    P = np.concatenate((N, np.array([1] + [0]*((-(N.size + 2)) % r) + [1])))
    n = P.size // r
    P = P.reshape(n, r)

    # Absorb input P into sponge S.
    S = secfld.array(np.zeros(1600, dtype=object))
    for i in range(n):
        U = P[i] + S[:r]
        S = mpc.np_update(S, slice(r), U)  # S[:r] = U
        S = keccak_f1600(S)

    # Squeeze output Z from sponge S.
    Z = S[:r]
    while len(Z) < d:
        S = keccak_f1600(S)
        Z = np.concatenate((Z, S[:r]))
    return Z[:d]

def keccak(c, N, d):
    """Keccak function with given capacity c and output length d applied to bit string N."""
    r = 1600 - c  # rate r satisfying r + c = b = 1600
    return sponge(r, N, d)

def sha3(M, d=256, c=128):
    """SHA3 hash of the given message M with output length d."""
    # append 01 to M
    N = np.concatenate((M, np.array([0, 1])))
    return keccak(c, N, d)

# check homomorphism with SHA3
async def main5():
    secint = mpc.SecInt(16)

    await mpc.start()

    n = 1
    c = 512
    d = c//2
    F = sha3
    f = {224: sha3_224, 256: sha3_256, 384: sha3_384, 512: sha3_512}[d]
    e = ()

    i = input("Give your input: ")
    X = i.encode() * n
    print(f'Input: {X}')
    x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
    x = secfld.array(x)  # secret-shared input bits

    inputs = mpc.input(x)
    print(type(inputs[0]))

    # convert bits to bytes again for concatenation
    x_bytes = np.packbits(await mpc.output(inputs[0]))

    #i = mpc.np_append(inputs[0], inputs[1])
    #i = mpc.np_concatenate(inputs[0], inputs[1])
    i = mpc.np_concatenate(inputs)

    #print("inputs concatenated: ", await mpc.output(i))

    y = F(i, d, c)  # secret-shared output bits
    Y = await xprint('Output:', y)
    assert Y == f(X).hexdigest(*e)

    print("input0: ", await mpc.output(inputs[0]))
    print("input1: ", await mpc.output(inputs[1]))
    mpc.shutdown()

# run this program with: python3 test_secobj.py -M2 -I0
# M indicates the number of parties
# I indicates the index of the current party

mpc.run(main5())