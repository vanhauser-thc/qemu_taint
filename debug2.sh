export QEMU_LOG=in_asm,op_opt
echo 000|/usr/bin/qemu-x86_64 -- ./test-instr
