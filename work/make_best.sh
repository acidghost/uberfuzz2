#!/usr/bin/env bash

set -e

TARGET=release
INTERVALS="../master/target/$TARGET/intervals"

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
  if [[ -e "$glob-$i/union.coverage.log" ]]; then
    mv "$glob-$i/union.coverage.log" "$glob-$i/union.coverage.log.bck"
  fi
  rm -f "$glob-$i/best.coverage.log"
  $INTERVALS -g "$glob-$i/*.coverage.log" -t $ticks -r -b -m > "$glob-$i/best.coverage.log"
  if [[ -e "$glob-$i/union.coverage.log.bck" ]]; then
    mv "$glob-$i/union.coverage.log.bck" "$glob-$i/union.coverage.log"
  fi
done

