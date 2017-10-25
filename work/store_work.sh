#!/usr/bin/env bash

stored_work="./stored_work"

if [ -z "$1" ]; then
  echo "usage: $0 folder"
  exit 1
fi

where="${stored_work}/$1"

if [ -d "${where}" ]; then
  echo "Directory ${where} exists"
  exit 1
fi

mkdir -p $where

conf_files="`ls *.conf`"

for conf_file in $conf_files; do
  arr=(${conf_file//./ })
  folder=${arr[0]}
  mv $folder "${where}/"
  mv $folder*.log "${where}/"
done
mv inputs.log "${where}/"
