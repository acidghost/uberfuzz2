#!/usr/bin/env bash

conf_files="`ls *.conf`"

rm -rf ./*.log

for conf_file in $conf_files; do
  arr=(${conf_file//./ })
  folder=${arr[0]}
  ftype=${arr[1]}
  echo "Setting up ${folder} (type ${ftype})"
  rm -rf $folder
  mkdir $folder
  pushd $folder > /dev/null
  rm -rf out in driver *.log
  mkdir -p out/inject/queue out/${folder} in driver
  echo A > in/seed
  popd > /dev/null
done
