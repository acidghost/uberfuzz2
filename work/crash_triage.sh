#!/usr/bin/env bash

bold=$(tput bold)
normal=$(tput sgr0)
hilightg=$bold$(tput setb 2)$(tput setf 7)

dir="$1"
cmd="$2"
args="$3"
FUZZERS="aflfast fairfuzz honggfuzz"
TRIAGE_CMDS_FILE=/tmp/triage_gdb_commands
TMP_CRASH=/tmp/ubercrash
AFL_AS_LIMIT=$[50 * 1024]
HON_AS_LIMIT=$[200 * 1024]
OLD_AS_LIMIT=`ulimit -v`

if [[ (! -d "$dir") || ("$cmd" = "") ]]; then
  echo "usage: $0 dir cmd [args...]"
  exit 1
fi

out="$dir/crashes.log"
truncate -s0 $out

echo "Working on $dir..."

crash_i=1
for fuzzer in ${FUZZERS[@]}; do
  echo "Processing $fuzzer..."
  case "$fuzzer" in
    aflfast|fairfuzz)
      folder="$fuzzer/out/$fuzzer/crashes"
      name="id*"
      as_limit=$AFL_AS_LIMIT
      ;;
    honggfuzz)
      folder="$fuzzer/out/$fuzzer"
      name="*.fuzz"
      as_limit=$HON_AS_LIMIT
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

    ulimit -Sv $as_limit
    $cmd $fargs > /dev/null 2>&1
    code=$?
    ulimit -v $OLD_AS_LIMIT

    if [[ $code -gt 128 && $code -lt 255 ]]; then
      echo "$hilightg $crash_i/$i/$nfiles - $fuzzer $normal `basename $file`"
      echo "Exited with code $code (`kill -l $[$code - 128]`)"

      rm -f $TMP_CRASH
      cat > $TRIAGE_CMDS_FILE <<CMDS
break main
run "$fargs" &> /dev/null
set \$rlim = &{0ll, 0ll}
call getrlimit(RLIMIT_AS, \$rlim)
set *\$rlim[0] = $as_limit * 1024
call setrlimit(RLIMIT_AS, \$rlim)
set logging file $TMP_CRASH
set logging redirect on
set logging on
continue
source ../../CERT_triage_tools/exploitable/exploitable.py
bt
exploitable
CMDS
      gdb -batch -x $TRIAGE_CMDS_FILE $cmd > /dev/null
      echo -e "Fuzzer: $fuzzer\nFile: $file" >> $TMP_CRASH

      h="`grep -i 'hash:' $TMP_CRASH | cut -f2 -d' '`"
      if [[ "$h" != "" && "`grep -e $h $out`" = "" ]]; then
        cat $TMP_CRASH >> $out
        echo "" >> $out
        crash_i=$[$crash_i + 1]
      fi
      ierr=$[$ierr + 1]
    fi

    i=$[$i + 1]
  done
done

rm -f $TMP_CRASH $TRIAGE_CMDS_FILE

echo "done $out ($[$crash_i - 1] unique crashes)"

