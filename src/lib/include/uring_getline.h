#ifndef _URING_GETLINE_H
#define _URING_GETLINE_H
#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <io_ipc.h>

#define BUFSIZE 1024
#define MAX_LINE 65535

struct file_io_t {
	int logfile_fd;
	off_t offset;
    struct io_uring ring;
    bool scnd_buf;
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
    uint32_t offset1, offset2;
    uint32_t rsize1, rsize2;
	char fbuf1[BUFSIZE];
	char fbuf2[BUFSIZE];
};

// Reads a single line from a file (buffered)
int uring_getline(struct file_io_t * fio_arg, 
                  char ** lineptr);

// Reads multiple lines from a file (buffered)
int uring_getlines(struct file_io_t * fio_arg, 
                   struct iovec * ivoecs, 
                   uint16_t vsize, 
                   uint16_t bufsize);

#endif