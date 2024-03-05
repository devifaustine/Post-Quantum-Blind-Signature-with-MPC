# This python script starts two instances of mpyc_sphincs_benchmark.py, one for user and one for signer
# it gives both instances the values - key pair and the message to be signed accordingly

import subprocess
import time
import threading
import concurrent.futures


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


def run_user(instance_name, input_a, input_b, event):
    process = subprocess.Popen(user, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Wait until the other instance connects
    event.wait()
    # Provide inputs
    process.stdin.write(f'{input_a}\n')
    process.stdin.flush()
    event.wait() 
    process.stdin.write(f'{input_b}\n')
    process.stdin.flush()
    
    # Get the output
    output, _ = process.communicate()
    print(f"Output of {instance_name} instance:", output)

def run_signer(instance_name, input_a, input_b, event):
    process = subprocess.Popen(signer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Wait until the other instance connects
    event.wait()
    # Provide inputs
    process.stdin.write(f'{input_a}\n')
    process.stdin.flush()
    event.wait()
    process.stdin.write(f'{input_b}\n')
    process.stdin.flush()
    
    # Get the output
    output, _ = process.communicate()
    print(f"Output of {instance_name} instance:", output)

# Create an event to coordinate the execution of both instances
event = threading.Event()


# Run both instances in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    future1 = executor.submit(run_user, "first", messages[0], keys[0], event)
    future2 = executor.submit(run_signer, "second", keys[0], messages[0], event)

    # Set the event to signal that both instances have connected
    event.set()

# Ensure that both instances have finished executing
future1.result()
future2.result()

"""
for i in range(len(keys)):
    for j in range(len(messages)):
        # Run both instances in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(run_user, "first", messages[0], keys[0], event)
            future2 = executor.submit(run_signer, "second", keys[0], messages[0], event)

            # Set the event to signal that both instances have connected
            event.set()

        # Ensure that both instances have finished executing
        future1.result()
        future2.result()

"""

# process has completed
print("Benchmark is done! Check bench_res.txt for results.")

