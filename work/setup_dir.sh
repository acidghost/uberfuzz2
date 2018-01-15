#!/usr/bin/env bash

seed="$1"
if [[ -d "${seed}" ]]; then
  seed_folder=1
  seed="`readlink -f $1`"
fi

conf_files="`ls *.conf`"

rm -rf accepted.log coverage.log inputs.log interesting.log winning.log won.log \
  *.png

for conf_file in $conf_files; do
  arr=(${conf_file//./ })
  folder=${arr[0]}
  ftype=${arr[1]}

  if [[ "$2" != "" && "$folder" != "$2" ]]; then
    continue
  fi

  echo "Setting up ${folder} (type ${ftype})"
  rm -rf ".${folder}.input" ".${folder}"* $folder*.log
  [[ -d $folder ]] || mkdir $folder
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
        if [[ "`mount -l | grep $folder/special`" != "" ]]; then
          echo -e "\tUnmounting special..."
          sudo umount special
        fi
        rm -rf special data inter keep imageOffset.txt
        mkdir -p special
        echo -e "\tMounting special..."
        sudo mount -t tmpfs -o size=1024M tmpfs special
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
