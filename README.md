# qemu_taint

First level taint implementation with qemu for linux user mode

## How to use with afl++

**not supported yet**

This is meant for [afl++](https://github.com/AFLplusplus/AFLplusplus).
Checkout afl++, then in the afl++ repository execute
`cd qemu_taint && ./build_qemu_taint.sh`.
To use it just add the -A flag to afl-fuzz.

## How to use stand-alone

### Building

`./build.sh`

Currently only x86_64 is tested for host and guest, others could work though.

### Running

Just run your target with `afl-qemu-taint -- program flags`.
To see any taint you have to tell the tool what do you want to taint.

#### Specify what do you want to taint

Set the environment variable `AFL_TAINT_INPUT`.
Valid/expected values:

  * empty, not set or `<`  -> stdin
  * a filename  -> this file (must be a full path!)

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

  * NR_remap_file_pages, NR_copy_file_range: these are not implemented in qemu: 
  * NR_sendfile, NR_sendfile64: write directly to a fd, so no memory access. This is not interpretated as taint. However a warning is given.
  * NR_truncate, NR_truncate64: only if it truncates to 0 we stop taining, otherwise it is ignored
  * NR_open_by_handle_at: not supported (PRs welcome)

3. Complex things will not be detected, e.g. a rename or symlink on the file.

4. No care for speed. It is fast enough but could be made faster.
