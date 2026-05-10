
#ifndef _AFL_QEMU_TAINT_H

#define _AFL_QEMU_TAINT_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

extern int TAINT_var_standalone;
extern int TAINT_var_is_file;
extern int TAINT_var_is_stdin;
extern int TAINT_var_is_shmem;
extern int TAINT_var_taint_open;
extern char *TAINT_var_filename;
extern int TAINT_var_debug;
extern int TAINT_var_trace;
extern unsigned char *TAINT_var_filemap;

void TAINT_func_fd_follow(int fd);
void TAINT_func_fd_unfollow(int fd);
int  TAINT_func_fd_is_tainted(int fd);
void TAINT_func_mem_check(uintptr_t mem, size_t len);
void TAINT_func_mem_mark(uintptr_t mem, size_t len);
void TAINT_func_mem_add(uintptr_t mem, size_t len, ssize_t offset);
void TAINT_func_mem_remove(uintptr_t mem, size_t len);
void TAINT_func_mem_move(uintptr_t mem_old, size_t len_old, uintptr_t mem_new, size_t len_new);
void TAINT_func_tmp_load(uint32_t tb, uint32_t dst, uintptr_t mem, size_t len);
void TAINT_func_tmp_store(uint32_t tb, uint32_t src, uintptr_t mem, size_t len);
void TAINT_func_tmp_clear(uint32_t tb, uint32_t dst);
void TAINT_func_tmp_copy(uint32_t tb, uint32_t dst, uint32_t src);
void TAINT_func_tmp_union2(uint32_t tb, uint32_t dst, uint32_t src1, uint32_t src2, int mark);
void TAINT_func_tmp_mark(uint32_t tb, uint32_t src);
void TAINT_func_tmp_trace_value(uint32_t tb, uint32_t src, uintptr_t pc, uint64_t value, const char *name, const char *insn);
void TAINT_func_tmp_trace_addr(uint32_t tb, uint32_t src, uintptr_t pc, uintptr_t addr, const char *kind, const char *insn);
void TAINT_func_offset_add(int fd, ssize_t offset);
void TAINT_func_offset_set(int fd, ssize_t offset);
long int TAINT_func_offset_get(int fd);
int  TAINT_func_filename_match(char *fname, int dfd);
void TAINT_func_reset(void);
void TAINT_func_end(void);

#endif
