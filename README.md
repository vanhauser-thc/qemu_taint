# qemu_taint

First level taint implementation with qemu for linux user mode

## How to use with afl++

**WIP**

This is meant for [afl++](https://github.com/AFLplusplus/AFLplusplus).
Checkout this special branch of afl++: [taint branch](https://github.com/AFLplusplus/AFLplusplus/tree/taint)
Then in the afl++ repository execute
`cd qemu_taint && ./build_qemu_taint.sh`.
To use it just add the -A flag to afl-fuzz.

## How to use stand-alone

### Building

`./build.sh`

Currently only x86_64 is tested for host and guest, others could work though.

### Running

Just run your target with `afl-qemu-taint -- program flags`.
By default the taint is gathered on stdin reads.
To see taint from files you have to set the environment variable
`AFL_TAINT_INPUT` with the full path to the input file.

#### The output

```
[TAINT] MAP (length: 56, shown: 56) ('!' = touched, '.' = untouched)
[ .!..!!!!....!!!!!!!!!!!!!!!!!!!!!!!.....................         ]
```

#### Debug output

Set `DEBUG=1` (or `AFL_DEBUG=1`).

This prints all the syscalls that touch the filename and tainted file
descriptors plus the tainted memory operations.

## Caveats

1. only tested for x86_x64 for host and guest (but could work elsewhere too)

2. Some syscall are not covered:

  * NR_remap_file_pages, NR_copy_file_range: these are not implemented in qemu
  * NR_sendfile, NR_sendfile64: write directly to a fd, so no memory access. This is not interpretated as taint. However a warning is given.
  * NR_[f]truncate, NR_[f]truncate64: only if it truncates to 0 we stop watching for `open*`, otherwise it is ignored
  * NR_open_by_handle_at: not supported (PRs welcome)

3. Complex things will not be detected, e.g. a rename or symlink on the file and then working on it.

4. No care for speed. It is fast enough but could be made faster.
