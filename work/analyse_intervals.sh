#!/usr/bin/env bash

set -e

TARGET=release
INTERVALS="../master/target/$TARGET/intervals"

glob=$1
ticks=$2
output=$3

if [[ ( "$glob" = "" ) || ("$ticks" = "") || ("$output" = "") ]]; then
  echo "usage: $0 glob ticks output [single_fuzzers]"
  exit 1
fi

shift 3

if [[ "$1" = "best" ]]; then
  $INTERVALS -g "${glob}/best.coverage.log" -t $ticks -m > "${output}.dat"
  gnuplot -p -c plot_ci.plt "${output}"
elif [[ "$1" != "" ]]; then
  for fuzzer in "$@"; do
    $INTERVALS -g "${glob}/${fuzzer}.coverage.log" -t $ticks -m -r > "${output}-${fuzzer}.dat"
    gnuplot -p -c plot_ci.plt "${output}-${fuzzer}"
  done
else
  $INTERVALS -g "${glob}/coverage.log" -t $ticks -m  > "$output.dat"
  gnuplot -p -c plot_ci.plt $output
fi;
