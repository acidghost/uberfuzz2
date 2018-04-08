#!/usr/bin/env bash

folder=$1
name=$2

if [[ ("$folder" = "") || ("$name" = "") ]]; then
  echo "usage: $0 folder filename"
  exit 0
fi

if [[ ! -d "$folder" ]]; then
  echo "'$folder' doesn't exist"
  exit 1
fi

while true; do
  LC_ALL="en_US.UTF-8" find $folder -name "${name}" -type f -mmin +0.16 -exec rm -rf {} \+ \
      2> >(grep -v 'Permission denied' >&2)
  sleep 2
done
