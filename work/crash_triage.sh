#!/usr/bin/env bash

bold=$(tput bold)
normal=$(tput sgr0)
hilightg=$bold$(tput setb 2)$(tput setf 7)

dir="$1"
cmd="$2"
args="$3"
FUZZERS="aflfast fairfuzz honggfuzz"
TRIAGE_CMDS_FILE=/tmp/triage_gdb_commands

if [[ (! -d "$dir") || ("$cmd" = "") ]]; then
  echo "usage: $0 dir cmd [args...]"
  exit 1
fi

cat > $TRIAGE_CMDS_FILE <<CMDS
run
source ../../CERT_triage_tools/exploitable/exploitable.py
bt
exploitable
CMDS

echo "Working on $dir..."

for fuzzer in ${FUZZERS[@]}; do
  echo "Processing $fuzzer..."
  case "$fuzzer" in
    aflfast|fairfuzz)
      folder="$fuzzer/out/$fuzzer/crashes"
      name="id*"
      ;;
    honggfuzz)
      folder="$fuzzer/out/$fuzzer"
      name="*.fuzz"
      ;;
    *)
      echo "Unrecognized fuzzer '$fuzzer'"
      exit 1
  esac

  OLDIFS=$IFS
  IFS=$'\n'
  files=(`find "$dir/$folder" -name "$name" -type f`)
  IFS=$OLDIFS

  nfiles=${#files[@]}
  i=1
  ierr=1
  echo "Found $nfiles files"
  for file in ${files[@]}; do
    fargs="${args/\$sub/$file}"
    $cmd $fargs > /dev/null 2>&1
    code=$?
    if [[ $code -gt 128 && $code -lt 255 ]]; then
      echo "$hilightg $ierr - $i/$nfiles - $fuzzer $normal `basename $file`"
      echo "Exited with code $code (`kill -l $[$code - 128]`)"
      gdb -batch -x $TRIAGE_CMDS_FILE --args $cmd $fargs
      ierr=$[$ierr + 1]
    fi
    i=$[$i + 1]
  done
done

rm $TRIAGE_CMDS_FILE

