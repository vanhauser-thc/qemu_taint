#!/bin/bash
test "$(uname -m)" = "x86_64" || echo Warning: only x86_64 is currently supported as host and target
test -e configure || exit 1
./configure --disable-system --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --enable-capstone=internal --target-list=x86_64-linux-user --enable-pie --python=/bin/python3 --disable-werror || exit 1
make || exit 1
cp -fv x86_64-linux-user/qemu-x86_64 ./afl-qemu-taint
