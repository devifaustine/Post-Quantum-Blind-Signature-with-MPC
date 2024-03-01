# test secure object in MPyC
import numpy as np
from mpyc.runtime import mpc
from mpyc.runtime import Runtime
from mpyc.gfpx import GFpX
from hashlib import sha3_224, sha3_256, sha3_384, sha3_512

# concatenate two arrays of secure objects
async def concatenate(array1, array2):
    print(type(array1))
    print(type(array2))
    return np.concatenate((array1, array2))

class Runtime2(Runtime):
    def __init__(self):
        super().__init__()

    def np_concatenate(self, arrays):
        return np.concatenate(arrays)

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
    print("Number 1: ", await mpc.output(ages[1]))
    print("Number 0: ", await mpc.output(ages[0]))

    # why is tmp == -42? because 3 * -14 = -42 = 14 * -3

    await mpc.shutdown()


# test subtraction of 2 numbers for (the first) 2 parties
# index of ages represent -I in the command line (not from who is the first to give the input)
async def main6():
    secfld = mpc.SecFld(2)
    await mpc.start()

    n = 1
    my_age = input("Enter your number: ")
    # convert input from bytes to bits
    X = my_age.encode() * n
    print("X is type: ", type(X))
    print(f'Input: {X}')
    x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
    y = secfld.array(x)  # secret-shared input bits
    print("my age: ", y)
    #ages = mpc.input(secfld.array(my_age))
    ages = mpc.input(y)
    print(type(ages))

    concat = mpc.np_concatenate(ages)
    #concat = mpc.np_concatenate((ages[0], ages[1]))

    seclist = mpc.seclist([ages[0], ages[1]])
    print("type list: ", type(seclist))

    #TODO: convert seclist to secarray

    print("Concat: ", concat)
    print("input1: ", await mpc.output(ages[0]))
    print("input2: ", await mpc.output(ages[1]))
    print("Array 1: ", await mpc.output(concat))
    #print("List 1: ", await mpc.output(seclist[0]))
    #pint("List 2: ", await mpc.output(seclist[1]))

    await mpc.shutdown()

# attempting sha3 with concatenated inputs of 2 parties
async def main7():
    secfld = mpc.SecFld(2)

    await mpc.start()

    # pre-defined variables for sha3
    n = 1
    c = 512
    d = c//2
    F = sha3
    f = {224: sha3_224, 256: sha3_256, 384: sha3_384, 512: sha3_512}[d]
    e = ()

    # receive inputs from command line
    in_ = input("Enter your number: ")

    # convert string to bytes
    X = in_.encode() * n
    print(f'Input: {X}')#

    # convert bytes to bits (array)
    if in_ == "123":
        import numpy as np2
        x = np2.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
    else:
        x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits

    # share inputs with parties using SSS
    inputs = mpc.input(secfld.array(x))

    # concatenating the inputs
    concat = mpc.np_concatenate((inputs[0], inputs[1]))

    # computing sha3 of the concatenated input
    y = F(concat, d, c)  # secret-shared output bits
    print("sha3 result: ", await mpc.output(y))
    #Y = await xprint('Output:', y)
    #assert Y == f(X).hexdigest(*e)

    await mpc.shutdown()

# test mpc.np_concatenate for two arrays a and b
async def main8():
    secfld = mpc.SecFld(2)
    await mpc.start()

    in_ = int(input("Give your input: "))

    if in_ == 1:
        import numpy as np2
        a = np2.array([in_])
    else:
        a = np.array([in_])
    b = np.array([4,5,6,7,8])

    inputs = mpc.input(secfld.array(a))
    print(inputs)

    # TODO: how to fix this?
    # if seca = inputs[1], the process will hang at this point and does not continue with the program
    # loops infinitely.
    seca = inputs[0]
    print(type(seca))
    secb = secfld.array(b)

    concat = mpc.np_concatenate((seca, secb))

    print("concatenated: ", await mpc.output(concat))

    await mpc.shutdown()

# TODO: try to create your own concatenate function for securearrays and not use np_concatenate from mpyc

# mpyc updated, problem fixed
# numpy also updated to fix the problem with np_concatenate
async def main11():
    secfld = mpc.SecFld(2)
    await mpc.start()

    # input has to be of same length so array works? (e.g. 10)
    in_ = input("Give your input: ")

    # pad the input to max length
    max = 10
    if len(in_) > max:
        raise ValueError("Input too long!")
    if len(in_) < max:
        in_ = pad(in_, max)

    assert len(in_) == max

    in_bit = ''.join(format(ord(i), '08b') for i in in_)
    print(in_bit)

    in_bit_list = [int(i) for i in in_bit]
    print(in_bit_list)

    inputs = mpc.input(secfld.array(np.array(in_bit_list)))

    # mpc.output() does not support outputting list
    for i in range(len(inputs)):
        print("input ", i, ": ", await mpc.output(inputs[i]))

    await mpc.shutdown()

# test input 0 = int, input 1 = list of ints
async def main13():
    secint = mpc.SecInt(16)
    await mpc.start()

    # input has to be of same length so array works? (e.g. 10)
    in_ = input("Give your input: ")
    res = [[]]
    try:
        res = int(in_)
        res = [secint(res), secint(0), secint(0)]
    except ValueError:
        lis = eval(in_)
        res = []
        for i in lis:
            res.append(secint(i))

    inputs = mpc.input(res)

    print("input 0: ", await mpc.output(inputs[0]))
    for i in inputs[1]:
        print("input 1: ", await mpc.output(i))

    x = await bigger(inputs[0][1], inputs[1])
    y = (inputs[0][0]).__gt__(inputs[1][2])
    print("input 0 > 1: ", await mpc.output(x))
    print("bigger? ", await mpc.output(y))

    await mpc.shutdown()

secint = mpc.SecInt(16)

async def bigger(a, b):
    if type(a) == list:
        tmp1 = secint(0)
        for i in a:
            tmp1 = mpc.add(tmp1, i)
    else:
        tmp1 = a
    if type(b) == list:
        tmp2 = secint(0)
        for x in b:
            tmp2 = mpc.add(tmp2, x)
    print("tmp1: ", await mpc.output(tmp1))
    print("tmp2: ", await mpc.output(tmp2))
    return tmp1.__gt__(tmp2)

# test convert bit array back to bytes
async def main12():
    secfld = mpc.SecFld(2)
    await mpc.start()

    # input has to be of same length so array works? (e.g. 10)
    in_ = input("Give your input: ")

    # pad the input to max length
    max = 10
    if len(in_) > max:
        raise ValueError("Input too long!")
    if len(in_) < max:
        in_ = pad(in_, max)

    assert len(in_) == max

    in_bit = ''.join(format(ord(i), '08b') for i in in_)
    print(in_bit)

    in_bit_list = [int(i) for i in in_bit]
    print(in_bit_list)

    inputs = mpc.input(secfld.array(np.array(in_bit_list)))

    # mpc.output() does not support outputting list
    for i in range(len(inputs)):
        print("input ", i, ": ", await mpc.output(inputs[i]))


    # converting bits to bytes
    concat = mpc.np_concatenate(inputs)
    s = await mpc.output(concat)
    s = np.fliplr(s.reshape(-1, 8)).reshape(-1)  # reverse bits for each byte
    d = len(s)
    s_binary = f'{int("".join(str(int(b)) for b in s), 2):0{d // 4}x}'  # Convert binary string to hexadecimal string
    s_bytes = bytes.fromhex(s_binary)  # Convert hexadecimal string to bytes
    print(s)
    print(type(s_bytes))

    print("concatenated byte: ", s_bytes)

    # decoding mostly results in unicode error
    #print("concatenated string: ", s_bytes.decode('utf-32'))

    await mpc.shutdown()

def pad(string, length):
    while len(string) < length:
        string += " "
    return string

# test bytestring as secure object
async def main10():
    secfld = mpc.SecFld(2)
    await mpc.start()

    in_ = input("Give your input: ")
    # encode() converts string to bytes

    # inputs have to be of the same length
    max_len = 10

    if len(in_) < max_len:
        in_ = pad(in_, max_len)

    in_bit = ''.join(format(ord(i), '08b') for i in in_)
    print(in_bit)


    in_bit_list = [int(i) for i in in_bit]
    print(in_bit_list)

    inputs = mpc.input(secfld.array(np.array(in_bit_list)))

    x = mpc.np_concatenate(inputs)
    print(type(x))
    print("concatenated: ", await mpc.output(x))

    await mpc.shutdown()

# test to_bytes function
async def main9():
    secint = mpc.SecInt(256)

    await mpc.start()

    in_ = input("Give your number: ")
    num = secint(int(in_))

    byt_num = mpc.to_bits(num)  # byt_num is a real list of secints
    print("length of number of the list: ", len(byt_num))

    inputs = mpc.input(num)

    sum = mpc.sum(inputs)

    print("bits: ", await mpc.output(byt_num))
    print("sum: ", await mpc.output(sum))
    print("bit sum: ", await mpc.output(mpc.to_bits(sum)))

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
    print("X is type: ", type(X))
    print(f'Input: {X}')
    x = np.array([(b >> i) & 1 for b in X for i in range(8)])  # bytes to bits
    Q = b'123'
    q = np.array([(b >> i) & 1 for b in Q for i in range(8)])  # bytes to bits

    print("type x before secfld.array: ", type(x))
    x = secfld.array(x)  # secret-shared input bits
    print("type x after secfld.array: ", type(x))

    baba = mpc.np_concatenate((x, q))
    print("baba is of type: ", type(baba))

    #TODO: resize array into same shape as same size (e.g. 256 bits)

    inputs = mpc.input(x)
    print(type(inputs[0]))
    print("inputs[1] is of type: ", type(inputs[1]))

    bibi = mpc.np_concatenate((inputs[1], inputs[1]))
    print("bibi is of type: ", type(bibi))

    i = mpc.np_concatenate((inputs[0], inputs[1]))
    #i = mpc.np_append(inputs[0], inputs[1])
#
 #   inputs_array = np.array(inputs)
  #  print("type inputsarray: ", type(inputs_array))
#
 #   inputs_array = secfld.array(inputs_array)
#
 #   print("type inputsarray: ", type(inputs_array))
    #inputs_array = mpc.SecureArray(inputs_array)
  #  print("isinstance array", isinstance(inputs_array, mpc.SecureArray))
   # print("now inputs is of type: ", type(inputs_array))
    # converting bits to bytes again for concatenation will not work as it is still Future and pending
    # this value will be determined once the program is done
    # x_bytes = np.packbits(await mpc.output(inputs[0]))

    #i = mpc.np_append(inputs[0], inputs[1])
    #i = mpc.np_concatenate(inputs[0], inputs[1])
    # concatenate inputs of (2) parties
    #i = concatenate(inputs[0], inputs[1])
#    i = mpc.np_concatenate(inputs_array)

    #TODO: change x with i - concatenation of the inputs


    #y = F(i, d, c)  # secret-shared output bits
    #Y = await xprint('Output sha3 of your inputs is:', y)
    #assert Y == f(X).hexdigest(*e)

    print("same inputs? ", mpc.np_equal(inputs[0], inputs[1]))
    print("input0: ", await mpc.output(inputs[0]))
    print("inputs concatenated: ", await mpc.output(bibi))
    print("i: ", await mpc.output(i))
    print("input1: ", await mpc.output(inputs[1]))
    await mpc.shutdown()

async def main16():
    secfld = mpc.SecFld(2)

    await mpc.start()

    pkroot = '100000101000111111110010100111111100011011110110100000100111010000010111001111011101101110110010110010010011101011011001110000001001001000100101111001001100010000100001110011110011011101100100111010000001111111100100100000000111101010010111011101011001111'
    pkseed = '101010101011001010100000101001001010011010011010101010101001001010001110011100001001111010110000101010001001000010100010100011001000111001100010011001101001010010010010011011101001110010001010101011000110010010001110011001000111001010001000100001101001001'
    skseed = '101001101010111010011000100001001010001010100110100111001001110010101100100110101001110010011110011011000110111001100110100111000110000010010100100101001000011001100000101011101001111010110010101010001011000010101100100001101000100010010110011010000110100'
    skprf = '11001100110110010100000011001101000101010011010101101001010001001110000100111101010011010110000011011101000101010010010100100001000100001101010011100001010011001110000100110100110100010101000011000100110111010011100101101001001000001110000101010101000101'

    payload = []

    for i in [pkroot, pkseed, skseed, skprf]:
        payload.append(secfld.array(np.array([int(j) for j in i])))

    inputs = mpc.input(payload)

    for i in payload:
        print("check: ", await mpc.output(i))

    await mpc.shutdown()

async def main14():
    secfld = mpc.SecFld(2)

    await mpc.start()

    inputs = input("Give your input: ")

    x = []
    for i in range(len(inputs)):
        x.append(ord(inputs[i]))

    payload = secfld.array(np.array(x))

    print("payload: ", payload)

    inputs_ = mpc.input(payload)

    concat = secfld.array(np.array([]))

    print("inputs: ", inputs_)

    for i in inputs_:
        concat = mpc.np_concatenate((concat, i))

    print("concatenated: ", await mpc.output(concat))

    for i in payload:
        print("check: ", await mpc.output(i))

    await mpc.shutdown()

async def main15():
    # test python indexing inside mpc
    secfld = mpc.SecFld(2)
    await mpc.start()

    inputs = input("Give your input: ")

    in_ = mpc.input(secfld(int(inputs)))

    # here's a list and a string we try to index later
    a = [1, 2, 3, 4, 5]
    b = "hello"

    # convert the list and string to secure objects
    a_sec = secfld.array(np.array(a))
    b_sec = secfld.array(np.array([ord(i) for i in b]))

    b_first = b[2:]
    a_first = a[1:]

    print(a_first)
    print(b_first)

    print("a: ", await mpc.output(a_sec))
    print("b: ", await mpc.output(b_sec))

    await mpc.shutdown()

# run this program with: python3 test_secobj.py -M2 -I0
# M indicates the number of parties
# I indicates the index of the current party

# TODO: Fix the following problem or find a solution for this
# main8 was successful as long as the second numpy is not used for some reasons
#mpc.run(main8())
#mpc.run(main9())
#mpc.run(main7())
#mpc.run(main10())
#mpc.run(main11())
#mpc.run(main12())
#mpc.run(main13())
#mpc.run(main14())
mpc.run(main15())