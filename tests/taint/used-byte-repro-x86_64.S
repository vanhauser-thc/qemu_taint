.globl _start

.text
_start:
    mov (%rsp), %rax
    cmp $2, %rax
    jl exit1

    mov %rax, %r14
    sub $32, %rsp
    mov %rsp, %r12

    xor %r15, %r15
    cmp $3, %r14
    jl read_input

    mov $2, %rax
    mov 56(%rsp), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    syscall
    test %rax, %rax
    jl exit1
    mov %rax, %r15

read_input:
    xor %rax, %rax
    mov %r15, %rdi
    mov %r12, %rsi
    mov $8, %rdx
    syscall
    test %rax, %rax
    jle exit1

    mov 48(%rsp), %r13
    mov (%r13), %eax

    cmpb $'a', %al
    je arith
    cmpb $'i', %al
    je index
    cmpb $'u', %al
    je unused
    cmpb $'c', %al
    jne exit1
    cmpb $'m', 2(%r13)
    je compare
    cmpb $'p', 2(%r13)
    je copy
    jmp exit1

compare:
    cmpb $'A', (%r12)
    sete %al
    jmp exit0

arith:
    movzbl 1(%r12), %eax
    add $3, %eax
    mov %eax, sink(%rip)
    jmp exit0

copy:
    mov 2(%r12), %al
    mov %al, 16(%r12)
    cmpb $'Z', 16(%r12)
    sete %al
    jmp exit0

index:
    movzbl 3(%r12), %eax
    and $7, %eax
    lea table(%rip), %rbx
    mov (%rbx,%rax,4), %eax
    mov %eax, sink(%rip)
    jmp exit0

unused:
    movl $1, sink(%rip)
    jmp exit0

exit0:
    xor %rdi, %rdi
    mov $60, %rax
    syscall

exit1:
    mov $1, %rdi
    mov $60, %rax
    syscall

.data
sink:
    .long 0
table:
    .long 1, 2, 3, 4, 5, 6, 7, 8
