#!/usr/bin/env bash

set -e

glob=$1
ticks=$2
output=$3
driver=''

if [[ ( "$glob" = "" ) || ("$ticks" = "") || ("$output" = "") ]]; then
  echo "usage: $0 glob ticks output [driver]"
  exit 1
fi

if [[ "$4" != "" ]]; then
  driver='-r'
fi;

../master/target/release/intervals -g "${glob}" -t $ticks -m $driver > "$output.dat"

gnuplot -p -c plot_ci.plt $output
