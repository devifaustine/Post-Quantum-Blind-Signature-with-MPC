# Post-Quantum-Blind-Signature-with-MPC
A simulation of a quantum-resistant blind signature scheme using Multi-Party Computation (MPC).

The idea is to use [SPHINCS+](https://sphincs.org/) to compute a quantum-resistant digital signature, and compute it inside the MPC, such that the parties involved do not learn anything from each other's private inputs.
In this setting there would only be 2 parties, the user and the signer. The signer's secret input would be the secret key, whereas the user input would be the message to be signed. These two inputs would be kept private from each other.
The user would then get the output at the end of the protocol, which is the signed message. 
The signature can then be verified using the signer's public key. 

We use the [SPHINCS+](https://sphincs.org/) signature scheme, which is stateless and hash-based as the base scheme for the blind signature. 

This implementation uses the help of [PySPX](https://github.com/sphincs/pyspx) library as reference, and also [MPyC](https://github.com/lschoe/mpyc), which is described [here](https://mpyc.readthedocs.io/en/latest/mpyc.html).

The goal is to benchmark this new scheme and determine if it is efficient in practice and can be used as a blind signature scheme.

To run the benchmark, run the following command:
```
./bench_mpc_sphincs.sh
```
This will run the benchmark for the MPC SPHINCS+ signature scheme, and output the results in the `results` folder.