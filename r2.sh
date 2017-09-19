#!/usr/bin/env bash

bold=`tput bold`
normal=`tput sgr0`

function usage {
  echo -e <<USAGE "${bold}Find extract info from a binary using radare2${normal}

  usage: `basename $0` [-x] [-f|b] binary

  options:  -h  prints this help
            -b  find basic blocks
            -f  find functions
            -x  prints addresses in hexadecimal format

  output bbs:   one row per basic block,
                columns: starting addr., ending addr. and size

  output fncs:  one row per function,
                columns: name, starting addr., ending addr. and size"
USAGE
  exit 1
}

hex_format=false
find_bbs=false
find_fcns=false
while getopts "xhbf", opt; do
  case "${opt}" in
    x)
      hex_format=true
      ;;
    b)
      if [ $find_fcns = true ]; then
        usage
      fi
      find_bbs=true;
      ;;
    f)
      if [ $find_bbs = true ]; then
        usage
      fi
      find_fcns=true;
      ;;
    *|h)
      usage
      ;;
  esac
done

if [ $find_bbs = false ] && [ $find_fcns = false ]; then
  usage
fi

shift $((OPTIND-1))
[ ! -e "$1" ] && usage

if [ $find_bbs = true ]; then
  r2script='afbj @@f'
  jqscript='.[] | "\(.addr) \(.addr + .size) \(.size)"'
  awkscript='{printf("0x%x 0x%x %d\n", $1, $2, $3)}'
elif [ $find_fcns = true ]; then
  r2script='aflj'
  jqscript='.[] | "\(.name) \(.offset) \(.offset + .size) \(.size)"'
  awkscript='{printf("%s 0x%x 0x%x %d\n", $1, $2, $3, $4)}'
fi

r2out=`r2 -q0 -A -c "$r2script" $1 | jq "$jqscript" | sed s/\"//g`

if [ $hex_format = true ]; then
  echo "$r2out" | awk "$awkscript"
else
  echo "$r2out"
fi
