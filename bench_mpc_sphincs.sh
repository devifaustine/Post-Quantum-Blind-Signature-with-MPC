#!/bin/bash

#TODO: these will be the parameters (256 bytes or something and the messages or sk that will change for each loop
#datasets=('a' 'b' 'c')
#sizes=(100 200 300)
#messages=('Y1WHLDCQAQZXB3CCC4CE6BC6C5ILOHM88U3VTTXZTOVFDBV5LHOXZU2U6AUMNLUI' 'X5ZLBS4B' '2IX9H85AYZRQE7PTFJTXVSU53UGF5G0ATXYDD89C2UCR5PNGZ' '1T85RQH5O7U9CYJJ76C9KRCGTUG30HAPSJZZUAEZCW4UUTR84CJVS6AR' 'FEMDWE8FQUC8JBAQF8H' )
#keys1=("(b'A2Z05G2DEXJ40O1VFSFTG0N26MDW0FTU\xfa\x07\xf4\xd4`\xfaR\xe3f\x1eG\xddY\x1a\xfc\xc6u\xcaGYrI%\xb4F`\xe4\xdc\xa3\xfe\x1f\xca', b'J3MLGFED7ACXJ39NTLCNRN0USILDNXOIHLV343HZGA2P2LXLKSHQBIS7D4YSINNJA2Z05G2DEXJ40O1VFSFTG0N26MDW0FTU\xfa\x07\xf4\xd4`\xfaR\xe3f\x1eG\xddY\x1a\xfc\xc6u\xcaGYrI%\xb4F`\xe4\xdc\xa3\xfe\x1f\xca')" "(b'A2Z05G2DEXJ40O1VFSFTG0N26MDW0FTU\xfa\x07\xf4\xd4`\xfaR\xe3f\x1eG\xddY\x1a\xfc\xc6u\xcaGYrI%\xb4F`\xe4\xdc\xa3\xfe\x1f\xca', b'J3MLGFED7ACXJ39NTLCNRN0USILDNXOIHLV343HZGA2P2LXLKSHQBIS7D4YSINNJA2Z05G2DEXJ40O1VFSFTG0N26MDW0FTU\xfa\x07\xf4\xd4`\xfaR\xe3f\x1eG\xddY\x1a\xfc\xc6u\xcaGYrI%\xb4F`\xe4\xdc\xa3\xfe\x1f\xca')" )

# split array input by newlines
IFS=$'\n'

#read -a arr <<< "$line"
# number of iteration for n key pairs
# TODO: note n is a list in python, find out what datatype it is in bash
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
    # TODO: give the private inputs once asked
  done
done

for dataset in "${datasets[@]}"; do
    for size in "${sizes[@]}"; do
        python script.py -d "$dataset" -s "$size"
    done
done
