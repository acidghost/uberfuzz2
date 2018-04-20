#!/usr/bin/env bash

if [[ "$ROUNDS" = "" ]]; then
  ROUNDS="01 02 03 04 05"
fi

if [[ "$PRINTDIFF" = "" ]]; then
  PRINTDIFF=0
fi

PROGNAME=$0

function do_average {
  local dirs=($@)
  [[ ${#dirs[@]} -lt 1 ]] && echo "usage: $PROGNAME average <dirs...>" && return 1
  for dir in ${dirs[@]}; do
    printf "Processing %s...\n -" "$dir"
    local total=0
    local nrounds=0
    for i in ${ROUNDS[@]}; do
      printf " %s" "$i"
      local f="$dir-$i/crashes.log"
      if [[ ! -e "$f" ]]; then
        echo -e "\n$f does not exist."
        return 1
      fi
      local uhs=`grep -i "hash:" $f | cut -f2 -d' ' | sort -u | wc -l`
      local uips=`grep -i "crash ip:" $f | cut -f3 -d' ' | sort -u | wc -l`
      total=$[$total + $uips]
      printf " (%d/%d)" "$uips" "$uhs"
      nrounds=$[$nrounds + 1]
    done
    local avg=`bc -l <<< "$total / $nrounds"`
    LC_NUMERIC=C printf "\n - Avg: %.3f\n" "$avg"
  done
  return 0
}

function do_diff {
  local dirs=("$1" "$2")
  if [[ "${dirs[0]}" = "" || "${dirs[1]}" = "" ]]; then
    echo "usage: $PROGNAME diff <dir1> <dir2>"
    return 1
  fi
  local ufiles=()
  for dir in ${dirs[@]}; do
    local gfile="/tmp/`basename $dir`"
    ufiles+=($gfile)
    truncate -s0 "$gfile"
    for i in ${ROUNDS[@]}; do
      local cf="$dir-$i/crashes.log"
      if [[ ! -e "$cf" ]]; then
        echo "$cf does not exist"
        return 1
      fi
      grep -i "crash ip:" "$cf" | cut -f3 -d' ' | sort -u >> $gfile
    done
  done
  local commonlens=`comm -12 <(cat "${ufiles[0]}" | sort -u) <(cat "${ufiles[1]}" | sort -u) | wc -l`
  for ufile in ${ufiles[@]}; do
    local l=`cat $ufile | sort -u | wc -l`
    local n=$[$l - $commonlens]
    echo "`basename $ufile`: $l total unique crashes, $n not discovered by the other"
  done
  if [[ "$PRINTDIFF" -eq 1 ]]; then
    echo -e "\ndiff:"
    comm -3 <(cat "${ufiles[0]}" | sort -u) <(cat "${ufiles[1]}" | sort -u)
  fi
  rm "${ufiles[0]}" "${ufiles[1]}"
  return 0
}

case "$1" in
  average)
    shift 1
    do_average $@
    exit $?
    ;;
  diff)
    do_diff $2 $3
    exit $?
    ;;
  *)
    echo "usage: $PROGNAME average|diff arguments"
    exit 1
esac

