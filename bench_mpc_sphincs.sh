#!/bin/bash

#TODO: these will be the parameters (256 bytes or something and the messages or sk that will change for each loop
#datasets=('a' 'b' 'c')
#sizes=(100 200 300)

# number of iteration for n key pairs
n={1..5}
# number of iteration for n2 messages (for a key pair i)
n2={1..10}

for i in n; do
  for j in n2; do
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I0&
    python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I1&
    # TODO: give the private inputs once asked
  done
done

for dataset in "${datasets[@]}"; do
    for size in "${sizes[@]}"; do
        python script.py -d "$dataset" -s "$size"
    done
done
