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
    rm -rf in driver *.log

    case $ftype in
      afl|hongg)
        rm -rf out
        if [[ $ftype = afl ]]; then
          inject_dir="out/inject/queue"
        else
          inject_dir="out/inject"
        fi
        mkdir -p $inject_dir out/${folder}
        ;;
      vu)
        rm -rf special data inter keep imageOffset.txt
        mkdir -p special
        echo A > image.offset
        ;;
      *)
        echo "Unrecognized fuzzer type for $conf_file: $ftype"
        popd > /dev/null
        exit 1
    esac
    mkdir driver

    if [[ $seed_folder -eq 1 ]]; then
      cp -r $seed "in"
    else
      mkdir "in"
      echo "${seed}" > in/seed
    fi
  popd > /dev/null
done
