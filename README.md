# Post-Quantum-Blind-Signature-with-MPC
A simulation of a quantum resistant blind signature scheme using Multi-Party Computation (MPC).

The idea is to use SPHINCS+ as a circuit to compute a Post-Quantum digital signature, and then put it inside the MPC, such that the parties doesn't know each other's input - the signer's input would then be the secret key, whereas the user input would be the message. 
The user would then get the output - signed message.

We use the [SPHINCS+](https://sphincs.org/) signature scheme, which is stateless and hash-based as the base scheme for the blind signature. 

This implementation uses the [PySpx](https://github.com/sphincs/pyspx.git) library, the package is described [here](https://pypi.org/project/PySPX/).

The goal is to benchmark this scheme and determine if it is efficient in practice and can be used as a blind signature scheme. 

We want the cost for the signer lower than the user's generally since the computation will mostly be done by the signer. 