#!/usr/bin/env bash

rm -rf $1
mkdir $1
pushd $1 > /dev/null
rm -rf out in *.log
mkdir out in
echo A > in/seed
popd > /dev/null
