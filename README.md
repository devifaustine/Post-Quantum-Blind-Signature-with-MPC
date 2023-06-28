# Post-Quantum-Blind-Signature-with-MPC
A simulation of a quantum resistant blind signature scheme using Multi-Party Computation (MPC).

We use the [SPHINCS+](https://sphincs.org/) signature scheme, which is stateless and hash-based as the base scheme for the blind signature. 

This implementation uses the [PySpx](https://github.com/sphincs/pyspx.git) library, the package is described [here](https://pypi.org/project/PySPX/).
The goal is to create a function that formulates the MPC (Multi-Party Computation) which takes a message and a secret key of the Signer to create the signature. 
Note that this also then needs a Post-Quantum Oblivious Transfer instead of a normal one. 

We want the cost for the signer lower than the user's generally since the computation will mostly be done by the signer. 