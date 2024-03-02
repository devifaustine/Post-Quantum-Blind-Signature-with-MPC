#!/bin/bash

#TODO: these will be the parameters (256 bytes or something and the messages or sk that will change for each loop

run_benchmark() {
  # split array input by newlines
  IFS=$'\n'

  # number of iteration for n key pairs
  read -a keys <<< "$(python3 sphincs/gen_keys_bench.py -n 3)"
  # number of iteration for n2 messages (for a key pair i)
  read -a mes <<< "$(python3 sphincs/gen_m_bench.py -n 5)"

  for key in "${keys[@]}"; do
    for m in "${mes[@]}"; do
      python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I0 <<< "$m
      $key"&
      # note: key has to be just the secret key, therefore public key has to be stored somewhere for verification
      python3 sphincs/mpyc_sphincs_benchmark.py -M2 -I1 <<< "$key
      $m"&
    done
  done > log.txt
}

run_benchmark
set -e

exit_code=$?

while true; do
  run_benchmark
  exit_code=$?

  if [ $exit_code -eq 0 ]; then
    echo "Running benchmark again."
  else
    echo "Benchmark successful."
    break
  fi
done

# TODO: make a table output in the command line for the results
#  or put the result table benchmark in the log.txt file
# exit the script
set -e