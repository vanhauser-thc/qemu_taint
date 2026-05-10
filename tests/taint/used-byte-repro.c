#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile unsigned int sink;

int main(int argc, char **argv)
{
    unsigned char buf[8] = { 0 };
    unsigned char out[8] = { 0 };
    int fd = 0;
    ssize_t len;

    if (argc >= 3) {
        fd = open(argv[2], O_RDONLY);
        if (fd < 0) {
            return 1;
        }
    }

    len = read(fd, buf, sizeof(buf));

    if (len <= 0 || argc < 2) {
        return 1;
    }

    if (strcmp(argv[1], "compare") == 0) {
        if (buf[0] == 'A') {
            sink++;
        }
    } else if (strcmp(argv[1], "arith") == 0) {
        sink += (unsigned int)(buf[1] + 3);
    } else if (strcmp(argv[1], "copy") == 0) {
        out[2] = buf[2];
        if (out[2] == 'Z') {
            sink++;
        }
    } else if (strcmp(argv[1], "index") == 0) {
        static unsigned int table[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        sink += table[buf[3] & 7];
    } else if (strcmp(argv[1], "unused") == 0) {
        sink++;
    } else {
        return 1;
    }

    return (int)(sink & 1);
}
