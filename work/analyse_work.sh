#!/usr/bin/env bash

set -e

nfuzzers=$1
work_path=$2
ticks=$3
timestep=60000

if [[ ( "$nfuzzers" = "" ) || ( "${work_path}" = "" ) || ("$ticks" = "")  ]]; then
  echo "usage: $0 nfuzzers work_path ticks [timestep]"
  exit 1
fi

if [[ ! -d "${work_path}" ]]; then
  echo "${work_path} is not a directory"
  exit 1
fi

if [[ "$4" != "" ]]; then
  timestep=$4
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

gnuplot -p -c $plot $coverage $(($nfuzzers + 1)) $ticks
gnuplot -p -c $plot $interesting $(($nfuzzers + 1)) $ticks

winning="${work_path}/winning.log"
accepted="${work_path}/accepted.log"
won="${work_path}/won.log"

../master/target/debug/winning -t $timestep -f $winning -a $accepted -w $won

gnuplot -p -c $plot $accepted $nfuzzers $ticks
gnuplot -p -c $plot $won $nfuzzers $ticks
