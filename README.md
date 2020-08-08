# qemu_taint

First level taint implementation with qemu for linux user mode

## How to use with afl++

This is meant for [afl++](https://github.com/AFLplusplus/AFLplusplus).
Checkout afl++, then in the afl++ repository execute
`cd qemu_taint && ./build_qemu_taint.sh`.
To use it just add the -A flag to afl-fuzz.

## How to use stand-alone

### Building

`./build.sh`

Currently only x86_64 is supported for host and guest.

### Running

Just run your target with `afl-qemu-taint -- program flags`.
To see any taint you have to tell the tool:

  1. What do you want to taint
  2. To print debug output.

#### Specify what do you want to taint

Set the environment variable `AFL_TAINT_INPUT`.
Valid/expected values:

  * empty, not set or `<`  -> stdin
  * a filename  -> this file (must be a full path!)

#### Specify you want to see ouput

Set `AFL_DEBUG=1`.
This prints more than just the touched byte offset though. But otherwise you
will not see any taint information :)

## Caveats

  * only tested for x86_x64 for host and guest
  * not sure everything is found :) needs testing if I did not miss anything
