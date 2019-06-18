#!/usr/bin/env bash

cloc --out=cloc.driver.txt --exclude-lang=make driver r2.sh
cloc --out=cloc.master.txt --exclude-dir=bin master/src
cloc --out=cloc.analysis.txt master/src/bin uberenv.sh work/*.{sh,plt}
cloc --sum-reports --out=uberfuzz cloc.{master,driver}.txt
cloc --sum-reports --out=uberfuzz.all cloc.*.txt

for t in "file" "lang" "all.file" "all.lang"; do
  mv "uberfuzz.$t" "uberfuzz.$t.txt"
  echo Moved "uberfuzz.$t" to "uberfuzz.$t.txt"
done
