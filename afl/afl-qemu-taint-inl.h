
#ifndef _AFL_QEMU_TAINT_INL_H

#define _AFL_QEMU_TAINT_INL_H

#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include "../config.h"

#define TAINT_TCG_MAX_TEMPS 512
#define TAINT_TCG_GLOBAL_ID 0x80000000u
#define TAINT_TCG_ID_MASK 0x7fffffffu

int TAINT_var_standalone;
int TAINT_var_is_file;
int TAINT_var_is_stdin = 1;
int TAINT_var_is_shmem;
int TAINT_var_taint_open;
int TAINT_var_debug;
int TAINT_var_trace;
ssize_t TAINT_var_stdin_offset;
char *TAINT_var_filename;
unsigned char *TAINT_var_filemap;

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

struct taint_range {
  unsigned int start;
  unsigned int end;
  struct taint_range *next;
};

struct tmp_shadow {
  uint32_t epoch;
  int has_addr;
  uintptr_t addr;
  struct taint_range *ranges;
};

struct shadow_mem_entry {
  uintptr_t addr;
  struct taint_range *ranges;
  struct shadow_mem_entry *next;
};

static struct fd_entry *fd_entries;
static struct mem_entry *mem_entries;
static struct shadow_mem_entry *shadow_mem_entries;
static struct tmp_shadow tmp_shadows[TAINT_TCG_MAX_TEMPS];
static ssize_t highest_offset = 0;

static void TAINT_func_ranges_free(struct taint_range *r) {
  while (r) {
    struct taint_range *n = r->next;
    free(r);
    r = n;
  }
}

static struct taint_range *TAINT_func_ranges_clone(struct taint_range *src) {
  struct taint_range *head = NULL, **tail = &head;
  while (src) {
    struct taint_range *r = (struct taint_range *) malloc(sizeof(*r));
    if (!r) {
      TAINT_func_ranges_free(head);
      return NULL;
    }
    r->start = src->start;
    r->end = src->end;
    r->next = NULL;
    *tail = r;
    tail = &r->next;
    src = src->next;
  }
  return head;
}

static void TAINT_func_ranges_add(struct taint_range **head,
                                  unsigned int start, unsigned int end) {
  struct taint_range *r;

  if (end < start) return;

  for (r = *head; r; r = r->next) {
    if (start <= r->end + 1 && end + 1 >= r->start) {
      if (start < r->start) r->start = start;
      if (end > r->end) r->end = end;
      return;
    }
  }

  r = (struct taint_range *) malloc(sizeof(*r));
  if (!r) return;
  r->start = start;
  r->end = end;
  r->next = *head;
  *head = r;
}

static void TAINT_func_ranges_union(struct taint_range **dst,
                                    struct taint_range *src) {
  while (src) {
    TAINT_func_ranges_add(dst, src->start, src->end);
    src = src->next;
  }
}

static void TAINT_func_ranges_mark(struct taint_range *ranges) {
  while (ranges) {
    unsigned int i = ranges->start;
    while (i <= ranges->end && i < MAX_FILE) {
      if (TAINT_var_filemap)
        TAINT_var_filemap[i] = '!';
      if (i == UINT_MAX) break;
      i++;
    }
    ranges = ranges->next;
  }
}

static struct tmp_shadow *TAINT_func_tmp_get(uint32_t tb, uint32_t id,
                                             int create) {
  uint32_t idx = id & TAINT_TCG_ID_MASK;
  int is_global = !!(id & TAINT_TCG_GLOBAL_ID);
  struct tmp_shadow *tmp;

  if (idx >= TAINT_TCG_MAX_TEMPS) return NULL;
  tmp = &tmp_shadows[idx];

  if (!is_global && tmp->epoch != tb) {
    TAINT_func_ranges_free(tmp->ranges);
    tmp->ranges = NULL;
    tmp->has_addr = 0;
    if (create)
      tmp->epoch = tb;
  }

  return tmp;
}

static struct shadow_mem_entry *TAINT_func_shadow_mem_find(uintptr_t addr) {
  struct shadow_mem_entry *m = shadow_mem_entries;
  while (m) {
    if (m->addr == addr)
      return m;
    m = m->next;
  }
  return NULL;
}

static struct shadow_mem_entry *TAINT_func_shadow_mem_get(uintptr_t addr) {
  struct shadow_mem_entry *m = TAINT_func_shadow_mem_find(addr);
  if (m) return m;

  m = (struct shadow_mem_entry *) malloc(sizeof(*m));
  if (!m) return NULL;
  m->addr = addr;
  m->ranges = NULL;
  m->next = shadow_mem_entries;
  shadow_mem_entries = m;
  return m;
}

static void TAINT_func_shadow_mem_remove(uintptr_t mem, size_t len) {
  struct shadow_mem_entry **pm = &shadow_mem_entries;
  while (*pm) {
    struct shadow_mem_entry *m = *pm;
    if (m->addr >= mem && m->addr < mem + len) {
      *pm = m->next;
      TAINT_func_ranges_free(m->ranges);
      free(m);
    } else {
      pm = &m->next;
    }
  }
}

static void TAINT_func_fd_clean(void) {
  if (fd_entries) {
    struct fd_entry *g, *f = fd_entries;
    while (f) {
      g = f->next;
      free(f);
      f = g;
    }
    fd_entries = NULL;
  }
}

static void TAINT_func_mem_clean(void) {
  if (mem_entries) {
    struct mem_entry *n, *m = mem_entries;
    while (m) {
      n = m->next;
      free(m);
      m = n;
    }
    mem_entries = NULL;
  }
}

static void TAINT_func_shadow_clean(void) {
  unsigned int i;

  TAINT_func_shadow_mem_remove(0, ~(size_t)0);

  for (i = 0; i < TAINT_TCG_MAX_TEMPS; i++) {
    TAINT_func_ranges_free(tmp_shadows[i].ranges);
    tmp_shadows[i].ranges = NULL;
    tmp_shadows[i].has_addr = 0;
    tmp_shadows[i].epoch = 0;
  }
}

void TAINT_func_reset(void) {
  TAINT_func_fd_clean();
  TAINT_func_mem_clean();
  TAINT_func_shadow_clean();
  if (!TAINT_var_is_shmem) {
    if (TAINT_var_filename) {
      TAINT_var_is_file = 1;
      TAINT_var_taint_open = 1;
    }
    else TAINT_var_is_stdin = 1;
  }
  TAINT_var_stdin_offset = 0;
  highest_offset = 0; 
}

void TAINT_func_fd_follow(int fd) {
  struct fd_entry *f = (struct fd_entry *) malloc(sizeof(struct fd_entry));
  if (!f) return;
  if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD follow %d\n", fd);
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

  if (fd < 0) return;

  if (fd == 0 && TAINT_var_is_stdin == 1) {
    if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD unfollow %d\n", fd);
    TAINT_var_is_stdin = 0;
  }

  if (fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd) {
        if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD unfollow %d\n", fd);
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
        if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD match %d\n", fd);
        return 1;
      }
      f = f->next;
    }
  }

  return 0;
}

static void TAINT_func_mem_collect(uintptr_t mem, size_t len,
                                   struct taint_range **ranges) {
  if (mem_entries) {
    struct mem_entry *m = mem_entries;
    while (m) {
      if ((m->active == 1) && (
          (mem >= m->start && mem <= m->end) ||
          (mem + len >= m->start && mem + len < m->end) ||
          (mem <= m->start && mem + len > m->end)
         )) {

        //if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM likely found mem=0x%lx len=%lu\n", mem, len);

        size_t index = 0;
        while (index < len) {
          if (mem + index >= m->start && mem + index <= m->end) {
            unsigned int offset = mem + index + m->offset - m->start;
            TAINT_func_ranges_add(ranges, offset, offset);
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM found mem=0x%lx file_offset=%u\n",
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

  for (size_t index = 0; index < len; index++) {
    struct shadow_mem_entry *m = TAINT_func_shadow_mem_find(mem + index);
    if (m)
      TAINT_func_ranges_union(ranges, m->ranges);
  }
}

void TAINT_func_mem_check(uintptr_t mem, size_t len) {
  struct taint_range *ranges = NULL;

  TAINT_func_mem_collect(mem, len, &ranges);
  TAINT_func_ranges_mark(ranges);
  TAINT_func_ranges_free(ranges);
}

void TAINT_func_mem_mark(uintptr_t mem, size_t len) {
  TAINT_func_mem_check(mem, len);
}

void TAINT_func_mem_add(uintptr_t mem, size_t len, ssize_t offset) {
  if (!len) return;
  struct mem_entry *m = (struct mem_entry *) malloc(sizeof(struct mem_entry));
  if (!m) return;
  if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM add mem=0x%lx len=%lu offset=%ld\n", mem, len, offset);
  if (offset + len > highest_offset)
    highest_offset = offset + len;
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
  TAINT_func_shadow_mem_remove(mem, len);

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
          if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu (full)\n", mem, len);
          m->active = 0;
          return;
        }
        if (mem <= m->start && len >= m->len && mem + len > m->end) {
          // complete removal, dont return, might match more
          if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu (full)\n", mem, len);
          m->active = 0;
        } else { // partial removal

          int split_len = 0;
          uintptr_t split_ptr = 0;

          if (mem > m->start) { // ending part is removed
            if (mem + len - 1 < m->end) { // uh a middle block is removed
              split_len = m->end - (mem + len - 1);
              split_ptr = mem + len;
            }
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu\n", mem, m->end + 1 - mem);
            m->len = mem - m->start;
            m->end = m->start + m->len - 1;
          }

          if (!split_len && mem + len - 1 < m->end) {
            // beginning part is removed
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM remove mem=0x%lx len=%lu\n", m->start, mem + len - m->start);
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
  size_t index, len = len_old < len_new ? len_old : len_new;

  for (index = 0; index < len; index++) {
    struct shadow_mem_entry *old = TAINT_func_shadow_mem_find(mem_old + index);
    if (old) {
      struct shadow_mem_entry *new = TAINT_func_shadow_mem_get(mem_new + index);
      if (new) {
        TAINT_func_ranges_free(new->ranges);
        new->ranges = TAINT_func_ranges_clone(old->ranges);
      }
    }
  }
  TAINT_func_shadow_mem_remove(mem_old, len_old);

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
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM move from mem=0x%lx len=%lu to mem=0x%lx len=%lu (full)\n", mem_old, len_old, mem_new, len_new);
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
          if (len_new >= diff) {
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM move from mem=0x%lx len=%lu to mem=0x%lx len=%lu\n", m->end, diff, mem_new, diff);
            TAINT_func_mem_add(mem_new, diff, m->offset + m->len);
          } else {
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM move from mem=0x%lx len=%lu to mem=0x%lx len=%lu\n", m->end, diff, mem_new, len_new);
            TAINT_func_mem_add(mem_new, len_new, m->offset + m->len);
          }
        }

        if (!split_len && mem_old + len_old - 1 < m->end) {
          // beginning part is moved
          diff = m->start - mem_old;
          if (len_new - diff >= len_old) {
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM move from mem=0x%lx len=%lu to mem=0x%lx len=%lu\n", m->start, mem_old + len_old - m->start, mem_new + diff, len_old);
            TAINT_func_mem_add(mem_new + diff, len_old, m->offset);
          } else {
            if (TAINT_var_debug) fprintf(stderr, "[TAINT] MEM move from mem=0x%lx len=%lu to mem=0x%lx len=%lu\n", m->start, mem_old + len_old - m->start, mem_new + diff, len_new - diff);
            TAINT_func_mem_add(mem_new + diff, len_new - diff, m->offset);
          }
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

void TAINT_func_tmp_load(uint32_t tb, uint32_t dst, uintptr_t mem, size_t len) {
  struct tmp_shadow *d = TAINT_func_tmp_get(tb, dst, 1);
  if (!d) return;

  TAINT_func_ranges_free(d->ranges);
  d->ranges = NULL;
  d->has_addr = 0;
  d->addr = mem;
  TAINT_func_mem_collect(mem, len, &d->ranges);
  d->has_addr = d->ranges ? 1 : 0;
}

void TAINT_func_tmp_store(uint32_t tb, uint32_t src, uintptr_t mem, size_t len) {
  struct tmp_shadow *s = TAINT_func_tmp_get(tb, src, 0);
  size_t index;

  if (!s || !s->ranges) return;

  TAINT_func_ranges_mark(s->ranges);
  for (index = 0; index < len; index++) {
    struct shadow_mem_entry *m = TAINT_func_shadow_mem_get(mem + index);
    if (!m) return;
    TAINT_func_ranges_free(m->ranges);
    m->ranges = TAINT_func_ranges_clone(s->ranges);
  }
}

void TAINT_func_tmp_clear(uint32_t tb, uint32_t dst) {
  struct tmp_shadow *d = TAINT_func_tmp_get(tb, dst, 1);
  if (!d) return;

  TAINT_func_ranges_free(d->ranges);
  d->ranges = NULL;
  d->has_addr = 0;
}

void TAINT_func_tmp_copy(uint32_t tb, uint32_t dst, uint32_t src) {
  struct tmp_shadow *d = TAINT_func_tmp_get(tb, dst, 1);
  struct tmp_shadow *s = TAINT_func_tmp_get(tb, src, 0);
  if (!d) return;

  TAINT_func_ranges_free(d->ranges);
  d->ranges = s ? TAINT_func_ranges_clone(s->ranges) : NULL;
  d->has_addr = s ? s->has_addr : 0;
  d->addr = s ? s->addr : 0;
}

void TAINT_func_tmp_union2(uint32_t tb, uint32_t dst, uint32_t src1,
                           uint32_t src2, int mark) {
  struct tmp_shadow *d = TAINT_func_tmp_get(tb, dst, 1);
  struct tmp_shadow *s1 = TAINT_func_tmp_get(tb, src1, 0);
  struct tmp_shadow *s2 = TAINT_func_tmp_get(tb, src2, 0);
  if (!d) return;

  if (mark) {
    if (s1) TAINT_func_ranges_mark(s1->ranges);
    if (s2) TAINT_func_ranges_mark(s2->ranges);
  }

  TAINT_func_ranges_free(d->ranges);
  d->ranges = NULL;
  d->has_addr = 0;
  if (s1) TAINT_func_ranges_union(&d->ranges, s1->ranges);
  if (s2) TAINT_func_ranges_union(&d->ranges, s2->ranges);
  if (s1 && s1->has_addr) {
    d->has_addr = 1;
    d->addr = s1->addr;
  } else if (s2 && s2->has_addr) {
    d->has_addr = 1;
    d->addr = s2->addr;
  }
}

void TAINT_func_tmp_mark(uint32_t tb, uint32_t src) {
  struct tmp_shadow *s = TAINT_func_tmp_get(tb, src, 0);
  if (!s) return;
  TAINT_func_ranges_mark(s->ranges);
}

static void TAINT_func_ranges_trace(struct taint_range *ranges, uintptr_t pc,
                                    const char *insn, const char *detail) {
  while (ranges) {
    unsigned int i = ranges->start;
    while (i <= ranges->end && i < MAX_FILE) {
      fprintf(stderr,
              "[TAINT_TRACE] pc=0x%lx offset=%u %s insn=%s\n",
              (unsigned long)pc, i, detail ? detail : "", insn ? insn : "");
      if (i == UINT_MAX) break;
      i++;
    }
    ranges = ranges->next;
  }
}

void TAINT_func_tmp_trace_value(uint32_t tb, uint32_t src, uintptr_t pc,
                                uint64_t value, const char *name,
                                const char *insn) {
  struct tmp_shadow *s = TAINT_func_tmp_get(tb, src, 0);
  char detail[128];

  if (!s || !s->ranges) return;

  if (s->has_addr) {
    snprintf(detail, sizeof(detail), "%s%svalue=0x%llx mem_addr=0x%lx",
             (name && name[0]) ? name : "",
             (name && name[0]) ? " " : "",
             (unsigned long long)value, (unsigned long)s->addr);
  } else {
    snprintf(detail, sizeof(detail), "%s%svalue=0x%llx",
             (name && name[0]) ? name : "",
             (name && name[0]) ? " " : "",
             (unsigned long long)value);
  }
  TAINT_func_ranges_trace(s->ranges, pc, insn, detail);
  TAINT_func_ranges_mark(s->ranges);
}

void TAINT_func_tmp_trace_addr(uint32_t tb, uint32_t src, uintptr_t pc,
                               uintptr_t addr, const char *kind,
                               const char *insn) {
  struct tmp_shadow *s = TAINT_func_tmp_get(tb, src, 0);
  char detail[128];

  if (!s || !s->ranges) return;

  snprintf(detail, sizeof(detail), "%s=0x%lx",
           (kind && kind[0]) ? kind : "addr", (unsigned long)addr);
  TAINT_func_ranges_trace(s->ranges, pc, insn, detail);
  TAINT_func_ranges_mark(s->ranges);
}

void TAINT_func_offset_add(int fd, ssize_t offset) {
  if (fd == 0 && TAINT_var_is_stdin && offset > 0)
    TAINT_var_stdin_offset += offset;
  if (TAINT_var_is_file && fd_entries) {
    struct fd_entry *f = fd_entries;
    while (f) {
      if (fd == f->fd && f->active == 1) {
        if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD offset add fd=%d offset+=%ld\n", fd, offset);
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
        if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD offset set fd=%d offset=%ld\n", fd, offset);
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
        if (TAINT_var_debug) fprintf(stderr, "[TAINT] FD offset get fd=%d offset==%ld\n", fd, f->offset);
        return f->offset;
      }
      f = f->next;
    }
  }

  return 0;
}

int TAINT_func_filename_match(char *fname, int dfd) {

  if (!TAINT_var_is_file) return 0;
  if (fname == NULL || fname[0] == 0) return 0;
  
  DIR *dir = NULL;
  int fd, ret = 0;
  char rpath[PATH_MAX];

  if (fname[0] != '/' && dfd >= 0) {
    dir = opendir(".");
    fd = dirfd(dir);
    if (fchdir(dfd) != 0) {
      closedir(dir);
      dir = NULL;
    }
  }

  if (realpath(fname, rpath) != NULL)
    if (strcmp(rpath, TAINT_var_filename) == 0)
      ret = 1;
  if (strcmp(fname, TAINT_var_filename) == 0)
    ret = 1;

  if (dir != NULL) {
    fd = fchdir(fd) == 0;
    fd += closedir(dir);
  }

  return ret;

}

void TAINT_func_end(void) {

  if (TAINT_var_standalone) {
  
    unsigned int i, j, len = highest_offset;
    if (len > MAX_FILE)
      len = MAX_FILE;
    
    fprintf(stderr, "[TAINT] MAP (length: %ld, shown: %d) ('!' = touched, '.' = untouched)\n", highest_offset, len);
    for (i = 0; i < len; i++) {
      if (i % 64 == 0) fprintf(stderr, "[ ");
      if (TAINT_var_filemap[i])
        fprintf(stderr, "!");
      else
        fprintf(stderr, ".");
      if (i % 64 == 63) fprintf(stderr, " ]\n");
    }
    
    j = highest_offset - len;
    if (j) {
      for (i = 0; i < j; i++) {
        if ((i + len) % 64 == 0) fprintf(stderr, "[ ");
        fprintf(stderr, "?");
        if ((i + len) % 64 == 63) fprintf(stderr, " ]\n");
      }
    }
    j = 64 - (len + j) % 64;
    if (j != 64) {
      for (i = 0; i < j; i++)
        fprintf(stderr, " ");
      fprintf(stderr, " ]\n");
    }

    TAINT_var_standalone = 0;
  
  }

}

#endif
