#include "benchmark.h"
#include <fips_buf.h>
#include <shm_ringbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct shm_buf_thread_arg {
  union process_arg_t {
    struct shmrbuf_writer_arg_t *writer_arg;
    struct shmrbuf_reader_arg_t *reader_arg;
  } process_arg;
  int thread_id;
  struct iovec iov[IOVLEN];
} shm_buf_thread_arg_t;

void *fips_buf_init_benchmark_process(void) {

  int retval = 0;

  if (!strcmp(benchmark_args.mode, "reader")) {

    int read_init = 0;
    struct shmrbuf_reader_arg_t *reader_struct;
    if ((reader_struct = (struct shmrbuf_reader_arg_t *)calloc(
             1, sizeof(struct shmrbuf_reader_arg_t))) == NULL) {
      perror("calloc of reader struct failed");
      exit(EXIT_FAILURE);
    };

    reader_struct->shm_key = SHM_PATH;

    if ((read_init = shmrbuf_init((union shmrbuf_arg_t *)reader_struct,
                                  SHMRBUF_READER)) != IO_IPC_SUCCESS) {
      fprintf(stdout, "reader status: %d\n", read_init);
      if (read_init != 0) {
        fprintf(stderr, "initalization of reader failed %d\n", read_init);
        free(reader_struct);
        exit(EXIT_FAILURE);
      }
    }
    return reader_struct;
  } else {
    struct shmrbuf_writer_arg_t *writer_struct =
        calloc(1, sizeof(struct shmrbuf_writer_arg_t));
    if ((writer_struct = (struct shmrbuf_writer_arg_t *)calloc(
             sizeof(struct shmrbuf_writer_arg_t), 1)) == NULL) {
      perror("calloc failed");
      exit(EXIT_FAILURE);
    };

    writer_struct->line_count = 1 << benchmark_args.line_count_exp;
    writer_struct->line_size = LINE_SIZE;
    writer_struct->segment_count = benchmark_args.num_threads;
    writer_struct->reader_count = 1;
    writer_struct->shm_key = SHM_PATH;
    writer_struct->flags = SHMRBUF_REATT | SHMRBUF_FRCAT; //| SHMRBUF_OVWR;

    if ((retval = shmrbuf_init((union shmrbuf_arg_t *)writer_struct,
                               SHMRBUF_WRITER)) != IO_IPC_SUCCESS) {
      fprintf(stderr, "Error on initilization of shared memory: %d \n",retval);
      fflush(stderr);
      shmrbuf_finalize((union shmrbuf_arg_t *)writer_struct, SHMRBUF_WRITER);
      exit(EXIT_FAILURE);
    } /* else {
      fprintf(stdout, "shmrbuf initilization succesful!\n");
    }*/
    return writer_struct;
  }
}

void *fips_buf_init_benchmark_thread(void *arg) {
  static _Atomic int thread_id = 0;
  shm_buf_thread_arg_t *shm_buf_targ = calloc(1, sizeof(shm_buf_thread_arg_t));
  shm_buf_targ->thread_id = thread_id++;
  for (int i = 0; i < IOVLEN; i++) {
    shm_buf_targ->iov[i].iov_base = malloc(LINE_SIZE);
    shm_buf_targ->iov[i].iov_len = LINE_SIZE;
  }
  if (!strcmp(benchmark_args.mode, "reader")) {
    shm_buf_targ->process_arg.reader_arg = arg;
  } else {
    shm_buf_targ->process_arg.writer_arg = arg;
  }
  return shm_buf_targ;
}

void *fips_buf_read_benchmark(void *arg) {
  shm_buf_thread_arg_t *targ = (shm_buf_thread_arg_t *)arg;
  int rsize = 0;
  int read_count = 0;

  while (read_count < IOVLEN) {
    if ((rsize = shmrbuf_readv_rng(
             targ->process_arg.reader_arg, targ->iov, IOVLEN - read_count,
             LINE_SIZE, targ->thread_id, targ->thread_id + 1, false)) < 0) {
      fprintf(stderr, "reading process failed %d\n", rsize);
      exit(EXIT_FAILURE);
    }
    handle_alarm();
    read_count += rsize;
  }
  return NULL;
}

void *fips_buf_write_benchmark(void *arg) {
  shm_buf_thread_arg_t *targ = (shm_buf_thread_arg_t *)arg;
  for (int i = 0; i < IOVLEN; i++) {
    targ->iov[i].iov_len = snprintf(targ->iov[i].iov_base, targ->iov[i].iov_len,
                                    "%s", string_generator(STRING_SIZE));
  }

  int written = 0;
  while (written < IOVLEN) {
    int ret = shmrbuf_writev(targ->process_arg.writer_arg, targ->iov,
                             IOVLEN - written, targ->thread_id);
    handle_alarm();

    if (ret >= 0) {
      written += ret;
    }
  }
  return NULL;
}

void *fips_buf_deinit_benchmark_thread(void *arg) { return NULL; }

void *fips_buf_deinit_benchmark_process(void *arg) {
  if (!strcmp(benchmark_args.mode, "reader")) {
    shmrbuf_finalize((union shmrbuf_arg_t *)arg, SHMRBUF_READER);
  } else {
    shmrbuf_finalize((union shmrbuf_arg_t *)arg, SHMRBUF_WRITER);
  }
  return NULL;
}

benchmark_functions_t register_benchmark(void) {
  benchmark_functions_t benchmark_functions;
  benchmark_functions.init_process = fips_buf_init_benchmark_process;
  benchmark_functions.init_thread = fips_buf_init_benchmark_thread;
  benchmark_functions.read = fips_buf_read_benchmark;
  benchmark_functions.write = fips_buf_write_benchmark;
  benchmark_functions.deinit_thread = fips_buf_deinit_benchmark_thread;
  benchmark_functions.deinit_process = fips_buf_deinit_benchmark_process;
  return benchmark_functions;
}
