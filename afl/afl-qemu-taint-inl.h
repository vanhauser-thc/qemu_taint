
#ifndef _AFL_QEMU_TAINT_INL_H

#define _AFL_QEMU_TAINT_INL_H

#include <sys/types.h>
#include <unistd.h>

int TAINT_var_is_file;
int TAINT_var_is_stdin = 1;
int TAINT_var_is_shmem;
int TAINT_var_taint_open = 1;
int TAINT_var_debug;
ssize_t TAINT_var_stdin_offset;
char *TAINT_var_filename = "/prg/tests/qemu/tiff-4.0.4/in/palette-1c-8b.tiff";

struct fd_entry {
  int active;
  int fd;
  ssize_t offset;
  struct fd_entry *next;
};

struct mem_entry {
  int active;
  uintptr_t start;
  uintptr_t end;
  size_t len;
  ssize_t offset;
  struct mem_entry *next;
};

static struct fd_entry *fd_entries;
static struct mem_entry *mem_entries;
static unsigned char filemap[1024000 / 8];

void TAINT_func_fd_follow(int fd) {
  struct fd_entry *f = (struct fd_entry *) malloc(sizeof(struct fd_entry));
  if (!f) return;
  if (debug) fprintf(stderr, "[TAINT] FD follow %d\n", fd);
  f->active = 1;
  f->fd = fd;
  f->offset = 0;
  if (fd_entries)
    f->next = fd_entries;
  else
    f->next = NULL;
  fd_entries = f;  
}

void TAINT_func_fd_unfollow(int fd) {

  if (fd == 0 && TAINT_var_is_stdin == 1) {
    if (debug) fprintf(stderr, "[TAINT] FD unfollow %d\n", fd);
    TAINT_var_is_stdin = 0;
  }

  if (fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd) {
        if (debug) fprintf(stderr, "[TAINT] FD unfollow %d\n", fd);
        f->active = 0;
        return;
      }
      f = f->next;
    }
  }
}

int TAINT_func_fd_is_tainted(int fd) {

  if (fd < 0) return 0;

  if (fd == 0 && TAINT_var_is_stdin) return 1;

  if (TAINT_var_is_file && fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd && f->active == 1) {
        fprintf(stderr, "[TAINT] FD match %d\n", fd);
        return 1;
      }
      f = f->next;
    }
  }

  return 0;
}

void TAINT_func_mem_check(uintptr_t mem, size_t len) {
  if (mem_entries) {
    struct mem_entry *m = mem_entries;
    while (m) {
      if ((m->active == 1) && (
          (mem >= m->start && mem <= m->end) ||
          (mem + len >= m->start && mem + len < m->end) ||
          (mem <= m->start && mem + len > m->end)
         )) {

        size_t index = 0;
        while (index < len) {
          if (mem + index >= m->start && mem + index < m->end) {
            unsigned int entry, bit, offset;
            offset = mem + index + m->offset - m->start;
            entry = offset / 8;
            bit = 1 << (offset % 8);
            filemap[entry] |= bit;
            fprintf(stderr, "[TAINT] MEM found mem=0x%lx file_offset=%u\n",
                    mem + index, offset);
          }
          index++;
        }

        if (mem >= m->start && mem + len < m->end)
          return;
      }
      m = m->next;
    }
  }
}

void TAINT_func_mem_add(uintptr_t mem, size_t len, ssize_t offset) {
  if (!len) return;
  struct mem_entry *m = (struct mem_entry *) malloc(sizeof(struct mem_entry));
  if (!m) return;
  if (debug) fprintf(stderr, "[TAINT] MEM add mem=0x%lx len=%lu offset=%ld\n", mem, len, offset);
  m->active = 1;
  m->start = mem;
  m->len = len;
  m->end = mem + len - 1;
  if (offset > 0)
    m->offset = offset;
  else
    m->offset = 0;
  if (mem_entries)
    m->next = mem_entries;
  else
    m->next = NULL;
  mem_entries = m;  
}

void TAINT_func_mem_remove(uintptr_t mem, size_t len) {
  if (mem_entries) {
    struct mem_entry *m = mem_entries;
    while (m) {

      if ((m->active == 1) && (
          (mem >= m->start && mem <= m->end) ||
          (mem + len >= m->start && mem + len < m->end) ||
          (mem <= m->start && mem + len > m->end)
         )) {

      if (m->start >= mem && m->end <= mem) {
        if (mem == m->start && len == m->len) {
          // complete removal, return
          if (debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu\n", mem, len);
          m->active = 0;
          return;
        }
        if (mem <= m->start && len >= m->len && mem + len > m->end) {
          // complete removal, dont return, might match more
          if (debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu\n", mem, len);
          m->active = 0;
        } else { // partial removal

          int split_len = 0;
          uintptr_t split_ptr = 0;

          if (mem > m->start) { // ending part is removed
            if (mem + len - 1 < m->end) { // uh a middle block is removed
              split_len = m->end - (mem + len - 1);
              split_ptr = mem + len;
            }
            m->len = mem - m->start;
            m->end = m->start + m->len - 1;
          }

          if (!split_len && mem + len - 1 < m->end) {
            // beginning part is removed
            uintptr_t diff = (mem + len) - m->start;
            m->start = (mem + len);
            m->len = m->end - m->start + 1;
            m->offset += diff;
          }

          if (split_len) {
            uintptr_t diff = (mem + len) - m->start;
            TAINT_func_mem_add(split_ptr, split_len, m->offset + diff);
          }
        }
        // no return. this might try to remove consecutive mems
      }
      }
      m = m->next;
    }
  }
}

void TAINT_func_mem_move(uintptr_t mem_old, size_t len_old, uintptr_t mem_new, size_t len_new) {
  if (mem_entries) {
    struct mem_entry *m = mem_entries;
    while (m) {
      if ((m->active == 1) && (
          (mem_old >= m->start && mem_old <= m->end) ||
          (mem_old + len_old >= m->start && mem_old + len_old < m->end) ||
          (mem_old <= m->start && mem_old + len_old > m->end)
         )) {
        if (mem_old == m->start && len_old == m->len) {
            // exact match - just update and return
            m->start = mem_new;
            if (len_new < m->len)
              m->len = len_new;
            m->end = mem_new + m->len - 1;
            return;
        }

        int split_len = 0;
        uintptr_t split_ptr = 0;
        uintptr_t diff;

        if (mem_old > m->start) { // ending part is moved
          if (mem_old + len_old - 1 < m->end) { // uh a middle block is moved
            split_len = m->end - (mem_old + len_old - 1);
            split_ptr = mem_old + len_old;
          }
          diff = m->len;
          m->len = mem_old - m->start;
          diff -= m->len;
          m->end = m->start + m->len - 1;
          if (len_new >= diff)
            TAINT_func_mem_add(mem_new, diff, m->offset + m->len);
          else
            TAINT_func_mem_add(mem_new, len_new, m->offset + m->len);
        }

        if (!split_len && mem_old + len_old - 1 < m->end) {
          // beginning part is moved
          diff = m->start - mem_old;
          if (len_new - diff >= len_old)
            TAINT_func_mem_add(mem_new + diff, len_old, m->offset);
          else
            TAINT_func_mem_add(mem_new + diff, len_new - diff, m->offset);
          diff = (mem_old + len_old) - m->start;
          m->start = (mem_old + len_old);
          m->len = m->end - m->start + 1;
          m->offset += diff;
        }

        if (split_len) {
          diff = (mem_old + len_old) - m->start;
          TAINT_func_mem_add(split_ptr, split_len, m->offset + diff);
        }
      }
      m = m->next;
    }
  }
}

void TAINT_func_offset_add(int fd, ssize_t offset) {
  if (fd == 0 && TAINT_var_is_stdin && offset > 0)
    TAINT_var_stdin_offset += offset;
  if (TAINT_var_is_file && fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd && f->active == 1) {
        if (debug) fprintf(stderr, "[TAINT] FD offset add fd=%d offset+=%ld\n", fd, offset);
        f->offset += offset;
        return;
      }
      f = f->next;
    }
  }
}

void TAINT_func_offset_set(int fd, ssize_t offset) {
  if (TAINT_var_is_file && fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd && f->active == 1) {
        if (debug) fprintf(stderr, "[TAINT] FD offset set fd=%d offset=%ld\n", fd, offset);
        if (offset > 0)
          f->offset = offset;
        else
          f->offset = 0;
        return;
      }
      f = f->next;
    }
  }
}

ssize_t TAINT_func_offset_get(int fd) {

  if (fd == 0 && TAINT_var_is_stdin)
    return TAINT_var_stdin_offset;

  if (TAINT_var_is_file && fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd && f->active == 1) {
        return f->offset;
      }
      f = f->next;
    }
  }

  return 0;
}

#endif
