# This python script starts two instances of mpyc_sphincs_benchmark.py, one for user and one for signer
# it gives both instances the values - key pair and the message to be signed accordingly

import subprocess

# Define the commands
user = ["python3", "mpyc_sphincs_benchmark.py", "-M2", "-I0"]
signer = ["python3", "mpyc_sphincs_benchmark.py", "-M2", "-I1"]

# Starts both processes
p1 = subprocess.Popen(user, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p2 = subprocess.Popen(signer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# provide input for user
p1.stdin.write("")
