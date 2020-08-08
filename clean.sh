#!/bin/sh
test -e configure || exit 1
make clean > /dev/null 2>&1
rm -f ./x86_64-linux-user/config-target.mak ./roms/seabios/config.mak \
 ./roms/vgabios/config.mak ./tests/qemu-iotests/common.env ./config.status \
 ./config-all-disas.mak ./config.log ./config-host.mak
make clean
rm -f afl-qemu-taint
