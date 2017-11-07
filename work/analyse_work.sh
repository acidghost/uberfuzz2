#!/usr/bin/env bash

set -e

nfuzzers=$1
work_path=$2
timestep=60000

if [[ ( "$nfuzzers" = "" ) || ( "${work_path}" = "" )  ]]; then
  echo "usage: $0 nfuzzers work_path [timestep]"
  exit 1
fi

if [[ ! -d "${work_path}" ]]; then
  echo "${work_path} is not a directory"
  exit 1
fi

if [[ "$3" != "" ]]; then
  timestep=$3
fi


inputs="${work_path}/inputs.log"
coverage="${work_path}/coverage.log"
interesting="${work_path}/interesting.log"
plot="plot.plt"

if [[ ! -e $inputs ]]; then
  echo "File ${inputs} does not exist"
  exit 1
fi

# replace './work' in inputs log with `work_path`
inputs_tmp="${inputs}.tmp"
sed "s,./work,${work_path},g" $inputs > $inputs_tmp
../master/target/debug/inputs -t $timestep -f $inputs_tmp -c $coverage -i $interesting
rm $inputs_tmp

gnuplot -p -c $plot $coverage $nfuzzers
gnuplot -p -c $plot $interesting $nfuzzers
