# uberfuzz2

### Dependencies and Compilation

**Master**
  - *deps* - [rust toolchain](https://www.rustup.rs/), library deps provisioned by cargo
  - *build* - run the following in the master directory `cargo build --release`

**Driver**:
  - *deps* - zeromq (install from distro repository), [Collections-C](https://github.com/srdja/Collections-C/)
  - *build* - use the provided `Makefile` in the driver folder


### Usage

First you have to create a configuration file for the fuzzer you want to run in
the `work` folder. The file name must be of the kind
`fuzzer_id.fuzzer_type.conf` where `fuzzer_id` is the identifier of the
configuration and fuzzer_type is one of `afl`, `hongg` or `vu`. The
configuration file contains the path to the fuzzer executable and all its
parameters, separated line by line.

Before running, you should setup the `work` directory accordingly. Within that
folder, run the `setup_dir.sh` script; this will setup directories for each
configuration file present. The script accepts one argument that can be a string
to be used as seed or a directory which contents are to be copied and used as
seed.

Based on the fuzzers you're planning to use, you may need to setup you system or
some environment variables: this can be done within the `uberenv.sh` script to
later be `source`d in the shell from which you'll run the fuzzers. Remember that
regardless of what fuzzer you're going to use it is advised that you turn off
ASLR.

The `master` executable accepts the following options:
```
usage: ./master/target/release/master [options] -- target [args]

Options:
    -h, --help          Print this help
    -f, --fuzzer aflfast
                        Fuzzer id (from id.type.conf in work directory)
    -H, --high          High or low winning strategy
    -t, --winning-threshold 0.42
                        Winning strategy threshold
    -s, --stdin         Target reads from standard input
    -B, --basic-blocks  Drivers use basic blocks from static analysis
    -S, --section       Drivers use only the .text section of the target
```

The `-f` flag identifies a configuration file. If the target reads from a file,
use the flag `--stdin` and a `@@` as a placeholder for the input file name. For
example:

`./master/target/release/master -f aflfst -f vuzzer -f honggfuzz -H -s -- djpeg @@`


### Run standalone drivers
```sh
timeout -k 3 $((60 * 60 * 4)) ./driver/driver -i vuzzer -f ./work/vuzzer.vu.conf \
  -c ./work/vuzzer/special -d ./work/vuzzer/driver \
  -l ./work/vuzzer.fuzz.log -L ./work/vuzzer.fuzz.err.log \
  -- ../libjpeg-turbo-1.5.1/djpeg ./work/.vuzzer.input

timeout -k 3 $((60 * 60 * 4)) ./driver/driver -i honggfuzz -f ./work/honggfuzz.hongg.conf \
  -c ./work/honggfuzz/in -d ./work/honggfuzz/driver \
  -l ./work/honggfuzz.fuzz.log -L ./work/honggfuzz.fuzz.err.log \
  -- ../libjpeg-turbo-1.5.1/djpeg ./work/.honggfuzz.input

timeout -k 3 $((60 * 60 * 4)) ./driver/driver -i fairfuzz -f ./work/fairfuzz.afl.conf \
  -c ./work/fairfuzz/out/fairfuzz/queue -d ./work/fairfuzz/driver \
  -l ./work/fairfuzz.fuzz.log -L ./work/fairfuzz.fuzz.err.log \
  -- ../libjpeg-turbo-1.5.1/djpeg ./work/.fairfuzz.input
```
