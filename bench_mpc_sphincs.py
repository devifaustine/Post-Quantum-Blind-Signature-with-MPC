# This python script starts two instances of mpyc_sphincs_benchmark.py, one for user and one for signer
# it gives both instances the values - key pair and the message to be signed accordingly

import subprocess
import time

logging = True

# get message inputs
with open("mes.txt", "r") as file:
    messages = [line.strip() for line in file]

# get key pair inputs
with open("keys.txt", "r") as file:
    keys = [line.strip() for line in file]

# Define the commands
user = ["python3", "sphincs/mpyc_sphincs_benchmark.py", "-M2", "-I0"]
signer = ["python3", "sphincs/mpyc_sphincs_benchmark.py", "-M2", "-I1"]

# Starts both processes
p1 = subprocess.Popen(user, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p2 = subprocess.Popen(signer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# provide input for user
p1.stdin.write(messages[0])
p1.stdin.flush()
p1.stdin.write(keys[0])
p1.stdin.flush()

# provide input for signer
p2.stdin.write(keys[0])
p2.stdin.flush()
p2.stdin.write(messages[0])
p2.stdin.flush()

"""
for i in range(len(keys)):
    for j in range(len(messages)):
        print("Signing message: ", messages[j], " with key: ", keys[i])
        # Define the commands
        user = ["python3", "mpyc_sphincs_benchmark.py", "-M2", "-I0"]
        signer = ["python3", "mpyc_sphincs_benchmark.py", "-M2", "-I1"]

        # Starts both processes
        p1 = subprocess.Popen(user, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p2 = subprocess.Popen(signer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # provide input for user
        p1.stdin.write(messages[j] + "\n")
        p1.stdin.write(keys[i] + "\n")

        # provide input for signer
        p2.stdin.write(keys[i] + "\n")
        p2.stdin.write(messages[j] + "\n")
"""

# wait for the processes to complete
p1.wait()
p2.wait()

output_user, error_user = p1.communicate()
output_signer, error_signer = p2.communicate()

while p1.poll() is None and p2.poll() is None:
    print("Process is still running. ")
    time.sleep(1)

# process has completed
print("Benchmark is done! Check bench_res.txt for results.")

"""
if logging:
    # printing out the logs from the processes
    for line in p1.stdout:
        print(line)
    for line in p2.stdout:
        print(line)
"""
