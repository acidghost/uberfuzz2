#!/usr/bin/env bash

seed="$1"
if [[ -d "${seed}" ]]; then
  seed_folder=1
  seed="`readlink -f $1`"
fi

conf_files="`ls *.conf`"

rm -rf ./*.log ./.input

for conf_file in $conf_files; do
  arr=(${conf_file//./ })
  folder=${arr[0]}
  ftype=${arr[1]}

  echo "Setting up ${folder} (type ${ftype})"
  rm -rf $folder ".${folder}.input" ".${folder}"*
  mkdir $folder
  pushd $folder > /dev/null
    rm -rf out in driver *.log
    mkdir -p out/inject/queue out/${folder} driver
    if [[ $seed_folder -eq 1 ]]; then
      cp -r $seed "in"
    else
      mkdir "in"
      echo "${seed}" > in/seed
    fi
  popd > /dev/null
done
