export QEMU_LOG=in_asm,out_asm,op_opt
echo 012|./qemu-test -- ./test-instr > err 2>&1
less err

