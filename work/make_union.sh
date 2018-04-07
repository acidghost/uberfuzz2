#!/usr/bin/env bash

set -e

TARGET=release
UNION="../master/target/$TARGET/union"

if [[ "$ROUNDS" = "" ]]; then
  ROUNDS="01 02 03 04 05"
fi

glob=$1
ticks=$2

if [[ ( "$glob" = "" ) || ("$ticks" = "") ]]; then
  echo "usage: $0 glob ticks"
  exit 1
fi

for i in ${ROUNDS[@]}; do
  echo "Processing $glob-$i..."
  $UNION -g "$glob-$i/{{fuzzer}}/driver/id*.coverage" -t $ticks \
    -f aflfast -f fairfuzz -f honggfuzz -f vuzzer > "$glob-$i/union.coverage.log"
done
