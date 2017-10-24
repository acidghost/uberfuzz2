#!/usr/bin/env bash

seed="$1"

conf_files="`ls *.conf`"

rm -rf ./*.log ./.input

for conf_file in $conf_files; do
  arr=(${conf_file//./ })
  folder=${arr[0]}
  ftype=${arr[1]}
  echo "Setting up ${folder} (type ${ftype})"
  rm -rf $folder ".${folder}.input"
  mkdir $folder
  pushd $folder > /dev/null
  rm -rf out in driver *.log
  mkdir -p out/inject/queue out/${folder} in driver
  echo "${seed}" > in/seed
  popd > /dev/null
done
