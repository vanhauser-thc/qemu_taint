/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

int main(int argc, char **argv) {

  char *buf = malloc(1024), buf2[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  unsigned int *x;
  DIR *d = opendir(".");
  int fd = dirfd(d);
  
  fprintf(stderr, "TAINT INTERNAL openat dirfd palette %d\n", fd);
  sprintf(buf, "ls -l /proc/%d/fd/%d", getpid(), fd);
  system(buf);

  read(0, buf, 1024);
  if (buf[1] == '1') {
    x = (unsigned int*)buf + 2;  
    if (*x == 0x34333231)
      printf("all ok\n");
    if (memcmp(buf + 6, buf2, 17) == 0)
      fprintf(stderr, "also fine\n");
  }
  return 0;
}
