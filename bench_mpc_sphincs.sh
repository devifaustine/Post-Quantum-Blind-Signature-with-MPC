#!/bin/bash

#TODO: these will be the parameters (256 bytes or something and the messages or sk that will change for each loop
#datasets=('a' 'b' 'c')
#sizes=(100 200 300)

# number of iteration for n key pairs
# TODO: note n is a list in python, find out what datatype it is in bash
keys=$(python3 gen_keys_bench.py -n 3)
# number of iteration for n2 messages (for a key pair i)
mes=$(python3 gen_m_bench.py -n 5)

for key in keys; do
  for m in mes; do
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I0 <<< m&
    # note: key has to be just the secret key, therefore public key has to be stored somewhere for verification
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I1 <<< key&
    # TODO: give the private inputs once asked
  done
done

for dataset in "${datasets[@]}"; do
    for size in "${sizes[@]}"; do
        python script.py -d "$dataset" -s "$size"
    done
done
