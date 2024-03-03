# Post-Quantum-Blind-Signature-with-MPC
A simulation of a quantum-resistant blind signature scheme using Multi-Party Computation (MPC).

PS: this repository is still under development and unofficial, and the code is far from perfect. It is a work in progress and is not yet ready for production use.

The idea is to use [SPHINCS+](https://sphincs.org/) to compute a quantum-resistant digital signature and compute it inside the MPC, such that the parties involved do not learn anything from each other's private inputs.
In this setting, there would only be 2 parties, the user and the signer. The signer's secret input would be the secret key, whereas the user input would be the message to be signed. These two inputs would be kept private from each other.
The user would then get the output at the end of the protocol, which is the signed message. 
The signature can then be verified using the signer's public key. 

We use the [SPHINCS+](https://sphincs.org/) signature scheme, which is stateless and hash-based as the base scheme for the blind signature. 

This implementation uses the help of [PySPX](https://github.com/sphincs/pyspx) library as a reference, and also [MPyC](https://github.com/lschoe/mpyc), which is described [here](https://mpyc.readthedocs.io/en/latest/mpyc.html).

The goal is to benchmark this new scheme and determine if it is efficient in practice and can be used as a blind signature scheme.

To run the benchmark, either run the following command:
```
./bench_mpc_sphincs.sh
```
This will run the benchmark for the MPC SPHINCS+ signature scheme, and output the results in the `results` file.
The ```bench_mpc_sphincs.sh``` script first generates the messages and the key pairs for signing. It then initializes and runs a python script, which runs two python3 instances running the SPHINCS+ built in MPC, one for the user/requester and one for the signer. Both instances will give the right inputs into the console (the user sends the message and the signer the key pair), and the SPHINCS+ signing function in MPC begins.

You can also directly run this command without generating new keypairs or messages:
```
python3 bench_mpc_sphincs.py
```

The `log.txt` file gives the log output of each instance of the python3 program running. The `bench_res.txt` file gives the time taken for the MPC SPHINCS+ signature scheme to run.

PS: The efficiency of the code could be improved more. The code is still under development and is not yet ready for production use.