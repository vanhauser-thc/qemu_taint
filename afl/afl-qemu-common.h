/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#ifndef __AFL_QEMU_COMMON
#define __AFL_QEMU_COMMON

#define PERSISTENT_DEFAULT_MAX_CNT 1000

#ifdef CPU_NB_REGS
  #define AFL_REGS_NUM CPU_NB_REGS
#elif TARGET_ARM
  #define AFL_REGS_NUM 16
#elif TARGET_AARCH64
  #define AFL_REGS_NUM 32
#else
  #define AFL_REGS_NUM 100
#endif

typedef void (*afl_persistent_hook_fn)(uint64_t *regs, uint64_t guest_base,
                                       uint8_t *input_buf,
                                       uint32_t input_buf_len);

/* Declared in afl-qemu-cpu-inl.h */

extern abi_ulong      afl_entry_point;
extern abi_ulong      afl_persistent_addr;
extern abi_ulong      afl_persistent_ret_addr;
extern unsigned char  afl_fork_child;
extern unsigned char  is_persistent;
extern target_long    persistent_stack_offset;
extern unsigned char  persistent_first_pass;
extern unsigned char  persistent_save_gpr;
extern uint64_t       persistent_saved_gpr[AFL_REGS_NUM];
extern int            persisent_retaddr_offset;

extern unsigned char * shared_buf;
extern unsigned int  * shared_buf_len;
extern unsigned char   sharedmem_fuzzing;

extern afl_persistent_hook_fn afl_persistent_hook_ptr;

void afl_setup(void);
void afl_forkserver(CPUState *cpu);

// void afl_debug_dump_saved_regs(void);

void afl_persistent_loop(void);

void afl_gen_tcg_plain_call(void *func);

/* Check if an address is valid in the current mapping */

static inline int is_valid_addr(target_ulong addr) {

  int          flags;
  target_ulong page;

  page = addr & TARGET_PAGE_MASK;

  flags = page_get_flags(page);
  if (!(flags & PAGE_VALID) || !(flags & PAGE_READ)) return 0;

  return 1;

}

#endif

