#!/bin/bash

#TODO: these will be the parameters (256 bytes or something and the messages or sk that will change for each loop

# split array input by newlines
IFS=$'\n'

#read -a arr <<< "$line"
# number of iteration for n key pairs
read -a keys <<< "$(python3 sphincs/gen_keys_bench.py -n 3)"
#keys=$(python3 sphincs/gen_keys_bench.py -n 3)
# number of iteration for n2 messages (for a key pair i)
read -a mes <<< "$(python3 sphincs/gen_m_bench.py -n 5)"
#mes=$(python3 sphincs/gen_m_bench.py -n 5)

for key in "${keys[@]}"; do
  for m in "${mes[@]}"; do
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I0 <<< "$m"&
    # note: key has to be just the secret key, therefore public key has to be stored somewhere for verification
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I1 <<< "$key"&
  done
done > results.txt
# TODO: make a table output in the command line for the results
#  or put the result table benhcmakr in the results.txt file