#!/usr/bin/env bash

conf_files="`ls *.conf`"

rm -rf ./*.log

for conf_file in $conf_files; do
  folder="${conf_file%.*}"
  echo "Setting up ${folder}"
  rm -rf $folder
  mkdir $folder
  pushd $folder > /dev/null
  rm -rf out in driver *.log
  mkdir out in driver
  echo A > in/seed
  popd > /dev/null
done
