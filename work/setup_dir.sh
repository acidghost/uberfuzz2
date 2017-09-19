#!/usr/bin/env bash

rm -rf $1
mkdir $1
pushd $1 > /dev/null
rm -rf out in driver *.log
mkdir out in driver
echo A > in/seed
popd > /dev/null
