# This executes a benchmark for the signing function of the official SPHINCS Library/Implementation,
# the PySPX library over different inputs

import pyspx.shake_256f
import pyspx.shake_128f
import random
import string
import time

# Create 2 seeds randomly, one for SHA128 the other for SHA256
x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(48))
y = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

list_seeds = [x, y]
seeds = []

# print out the seeds
for i in range(len(list_seeds)):
    if i == 1:
        print("seed SHA-128 = %s" %list_seeds[i])
    else:
        print("seed SHA-256 = %s" % list_seeds[i])
    seeds.append(bytes(list_seeds[i], 'ascii'))

# Randomly generate 100 messages of random length (1-70) to be signed later on
messages = []

# print("Messages: ")
# generating messages to be signed / payload
for i in range(100):
    length = random.randint(1, 70)
    message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    messages.append(bytes(message, 'ascii'))
    # prints out generated messages
    #print("\t %s" %message)

# list of elapsed time for SPHINCS using SHA128
time_128 = []
# list of elapsed time for SPHINCS using SHA256
time_256 = []
# list of elapsed time for keygen SPHINCS using SHA128
time_key_128 = []
# list of elapsed time for keygen SPHINCS using SHA256
time_key_256 = []
# list of elapsed time for verify SPHINCS using SHA128
time_ver_128 = []
# list of elapsed time for verify SPHINCS using SHA256
time_ver_256 = []

# Test verify function
sig2 = "b1f67e538bb9d4c2ef860f50085bcb72c10fb38ab696949b9417ddbefe8e4cad77a2617d410d8f1acd1fbc29830e1a51150d6ff09ca91ddf2411d40d6cdb428b026a5503246178066c93cc0092dfb834d31eba4a04674ee4689fb4e3ed25bff10b8e1eee0d920843fd1fa58d0999910c5bd82336fc1b558b09cf4e9592f48aaac52b3b20e164cbcc024bb6dfdd30dcf0db3c9137373c8b3d6a5d68315bf2572162ff648a0b8a14d2aa53e5f8e2762ff4dbf6b3c9609bece1375a18faf9962d80d68669200d87a879a029bf7c37af7d6ab64fa6544cd8b9cc36004eac37c7c7715c063348a39c93c97e8e41c98a0fa2a08e9c88e4333d6ec17b80f8bfc18f5cd016f8dfe04ed945c50d4e5cf9d0d1537183241c5423cb3d533bf2486573cf20735736f23e9605858c330b4e41739cf1eb0d36b728db77e9c7d8c2a6a55efa25ce3e57a6554a20c7773a4b4947835806d01817994ac7315ea97210ad8bf233e34eb91ba74995a7c56cc9429d0c41bdc3306ccc6560bbb41cefdd84b721a71fc8e4eb723498de8e8bcc16cd519b9550d42c5f680a61d512137abf4b21b791445522a82ee59116003cfc24f4f6db91935e034c358db13283920ba98b36857a1a701a957b1c4b3b247ad9450396961ba22afe3fe207dc774a40ed84ceaf9a6f235905640cbc05b48c8f483040f86c1cda2bdf6c2e12d209fef5c0ba25bc8b7e35393ea0fcf6a9be5881529356b059d6008da42ea77a023b3f8793ea9847162cdc6e6a192776c6db11c1c2294c49f3d202b6bc99b27518ce6c12caedf831b90167837b2ba3440e4d82b6076b76df0adf4dd6963d8081d64ff7f84307904c0f9e5e44e3ed3e575f3a6cc257b673679d118e8ff8894d76a527397ba9781c226f7a310273cc03bafa995bffca0da96529a1b3cbd7a11e8ddf7138b6240a99323202a0ceeab86426b7c60781bc0ac159ab308dcef30b5100ae9d5763931d9b8903b58499a54c11413ce7fecb75cdd011e03d71ffd83a9a69adfc44d551343084c2d1f43ff36ce036285d926a16fd27097d18d5ed548c550326b3369d81c9be5acd0a4a2a72fc3f842c09e7cccd566a1757e335cbc62c67fd3c20dee646ab01a237477d7352b79af58c11b3a3ec74b784ebc6e555447e1a202fc228647e3dc640ebde0bd56bf9231efd82f81f80193557bdafe79adbf9c79314f28513a9e3c850a65d25bff8f733055db6f51e2c3fa31502917de7893e22445ee9290487b77eee1080eb4144e1173259f7e05facc872146abc90e39a402d9d2ceb0ad2c2549b8e21a736e812f4306e18c3f8122aa2dc7b496613a369c3be605dbaa405e169aa6727401dc32ee9353703bc91c4fa75814fd4b9f517d47739fc53c97de8964364105c0dd9339f81dd6b5970f6b9ce2c8338d731c50c07fa1ef7c928518b1afdebddd1b83a3b665fae6d71863b4207d39e61823b59c6a9220f10bd9e03c371b229a79489601278"
PKseed = 'B505D7CFAD1B497499323C8686325E47'
PKroot = '4FDFA42840C84B1DDD0EA5CE46482020'
pk = PKseed + PKroot  # pk = B505D7CFAD1B497499323C8686325E474FDFA42840C84B1DDD0EA5CE46482020
print("pk = ", pk)
print()

# Testing split messages
message = b'Hello World'
pk, sk = pyspx.shake_256f.generate_keypair(seeds[1])
print(pk)
m1 = message[:len(message)//2]
m2 = message[len(message)//2:]
print("m1 = ", m1)
print("m2 = ", m2)
sig1 = pyspx.shake_256f.sign(m1, sk)
sig2 = pyspx.shake_256f.sign(m2, sk)
sig = pyspx.shake_256f.sign(message, sk)
print()
print("length of sig1 = ", len(sig1))
print("length of sig2 = ", len(sig2))
print("length of sig = ", len(sig))
print()
print("sig1 = ", sig1)
print("sig2 = ", sig2)
print("sig = ", sig)
print()

# benchmark the keygen(), sign() and verify()
for i in range(len(messages)):
    # Signing using SHA-128
    # generate public and private key pair
    start_key = time.time()
    public_key, secret_key = pyspx.shake_128f.generate_keypair(seeds[0])
    end_key = time.time()
    print("here's the public key: ", public_key)
    print("here's the secret key: ", secret_key)
    time_key_128.append(end_key - start_key)
    #print("secret key of SHA-128 is: ", secret_key)

    # sign the message
    start = time.time()
    signature = pyspx.shake_128f.sign(messages[i], secret_key)
    end = time.time()
    time_128.append(end - start)


    # verify the signature
    start_ver = time.time()
    ver = pyspx.shake_128f.verify(messages[i], signature, public_key)
    end_ver = time.time()
    time_ver_128.append(end_ver - start_ver)

    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

    # Signing using SHA-256
    # keygen using SHA256
    start_key_2 = time.time()
    public_key, secret_key = pyspx.shake_256f.generate_keypair(seeds[1])
    end_key_2 = time.time()
    print("here's the public key: ", public_key)
    print("here's the secret key: ", secret_key)
    time_key_256.append(end_key_2 - start_key_2)
    #print("secret key of SHA-256 is: ", secret_key)

    # sign the message using SHA256
    start = time.time()
    signature = pyspx.shake_256f.sign(messages[i], secret_key)
    end = time.time()
    print("here's the length of the signature: ", len(signature))
    time_256.append(end - start)

    # verify the signature using SHA256
    start_ver_2 = time.time()
    ver = pyspx.shake_256f.verify(messages[i], signature, public_key)
    end_ver_2 = time.time()
    time_ver_256.append(end_ver_2 - start_ver_2)

    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

#print("Average time to sign messages using SHA-128 = %d" %(mean(time_128)))
#print("Average time to sign messages using SHA-256 = %d" %(mean(time_256)))
#print(time_128)
#print(time_256)

elapsed_128 = 0
elapsed_256 = 0

for i in range(len(time_128)):
    elapsed_128 += time_128[i]
for i in range(len(time_256)):
    elapsed_256 += time_256[i]

# prints out the average time results - needs to be divided by 100, since it is
# the sum of time it takes to sign 100 messages
print("Time required for sign() using SHA128 is %d seconds." %elapsed_128)
print("Time required for sign() using SHA256 is %d seconds." %elapsed_256)
print("SHA128 is %d times faster than SHA256" %(elapsed_128/elapsed_256))
print()

print("here's the time for keygen() using SHA128: ", time_key_128)
print()
print("here's the time for keygen() using SHA256: ", time_key_256)
print()

print("here's the time for verify() using SHA128: ", time_ver_128)
print()
print("here's the time for verify() using SHA256: ", time_ver_256)
"""

# Average Time
elapsed_128 = 0
elapsed_256 = 0
for i in range(len(time_128)):
    elapsed_128 += time_128[i]
print("Average time to sign messages using SHA-128 = %d" %(elapsed_128/len(messages)))
for i in range(len(time_256)):
    elapsed_256 += time_256[i]
print("Average time to sign messages using SHA-256 = %d" %(elapsed_256/len(messages)))


"""