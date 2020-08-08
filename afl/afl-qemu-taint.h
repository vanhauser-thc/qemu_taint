
#ifndef _AFL_QEMU_TAINT_H

#define _AFL_QEMU_TAINT_H

#include <sys/types.h>
#include <unistd.h>

extern int TAINT_var_is_file;
extern int TAINT_var_is_stdin;
extern int TAINT_var_is_shmem;
extern int TAINT_var_taint_open;
extern char *TAINT_var_filename;

void TAINT_func_fd_follow(int fd);
void TAINT_func_fd_unfollow(int fd);
int  TAINT_func_fd_is_tainted(int fd);
void TAINT_func_mem_check(uintptr_t mem, size_t len);
void TAINT_func_mem_add(uintptr_t mem, size_t len, ssize_t offset);
void TAINT_func_mem_remove(uintptr_t mem, size_t len);
void TAINT_func_mem_move(uintptr_t mem_old, size_t len_old, uintptr_t mem_new, size_t len_new);
void TAINT_func_offset_add(int fd, ssize_t offset);
void TAINT_func_offset_set(int fd, ssize_t offset);
long int TAINT_func_offset_get(int fd);

void TAINT_func_reset(void);

#endif

