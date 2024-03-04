# compares SHA-256 vs. SHAKE256

import hashlib
import random 
import string
import time 

n = 100 

mes = []
# generate n random messages
for i in range(n):
    mes.append(''.join(random.choice(string.ascii_letters + string.digits)))

shake_hash = hashlib.shake_256()
sha_hash = hashlib.sha256()

time_sha = []
time_shake = []

for m in mes: 
    m = m.encode('utf-8')
    # timer for SHA256
    hashval = sha_hash.update(m)
    start = time.time() 
    digest = sha_hash.digest()
    end = time.time() 
    time_sha.append(end-start)

    # timer for SHAKE256
    shake_hash.update(m)
    start1 = time.time() 
    digest = shake_hash.digest(8 * 32)
    end1 = time.time() 
    time_shake.append(end1-start1)

print("Time taken for sha-256: ", time_sha)
print()
print("Time taken for shake-256: ", time_shake)