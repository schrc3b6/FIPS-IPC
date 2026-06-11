#include "benchmark.h"
#include <fips_buf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void *fips_buf_init_benchmark_process(void) {
  fips_buf_arg_t *fips_buf_parg = calloc(1, sizeof(fips_buf_arg_t));
  if (fips_buf_parg == NULL) {
    return NULL;
  }
  if (!strcmp(benchmark_args.mode, "reader")) {
    fips_buf_parg->role = FIPS_READER;
  } else {
    fips_buf_parg->role = FIPS_WRITER;
  }
  //fips_buf_parg->shm_name = SHM_PATH;
  //fips_buf_parg->line_size = LINE_SIZE;
  //fips_buf_parg->max_sqe_count = 1024;
  //fips_buf_parg->line_count_exp = benchmark_args.line_count_exp;
  //fips_buf_parg->max_reader_count = 4;
  //fips_buf_parg->max_reader_thread_count = 32;
  //fips_buf_parg->max_segment_count = 32;
  if (fips_buf_init(fips_buf_parg,"/etc/fips_buf.conf") != FIPS_BUF_SUCCESS) {
    free(fips_buf_parg);
    return NULL;
  }

  return fips_buf_parg;
}

void *fips_buf_init_benchmark_thread(void *arg) {
  fips_buf_thread_arg_t *fips_buf_targ =
      calloc(1, sizeof(fips_buf_thread_arg_t));
  fips_buf_targ->process_arg = arg;
  if (fips_buf_attach(fips_buf_targ) != FIPS_BUF_SUCCESS) {
    free(fips_buf_targ);
    return NULL;
  }
  return fips_buf_targ;
}

void *fips_buf_read_benchmark(void *arg) {
  struct iovec iov[IOVLEN];
  uint64_t tag;

  int ret = FIPS_BUF_SUCCESS;
  do {
    ret = fips_buf_read(arg, iov, IOVLEN, &tag, 0);
    handle_alarm();
  } while (ret != FIPS_BUF_SUCCESS);
  fips_buf_return(arg, tag);
  return NULL;
}

void *fips_buf_write_benchmark(void *arg) {
  struct iovec iov[IOVLEN];
  int ret = FIPS_BUF_SUCCESS;

  do {
    ret = fips_get_write_buffer(arg, iov, IOVLEN);
    handle_alarm();
  } while (ret != FIPS_BUF_SUCCESS);
  for (int i = 0; i < IOVLEN; i++) {
    iov[i].iov_len =
        snprintf(iov[i].iov_base, iov[i].iov_len, "%s", string_generator(STRING_SIZE));
  }
  fips_buf_write(arg, iov, IOVLEN);

  return NULL;
}

void *fips_buf_deinit_benchmark_thread(void *arg) { 
  fips_buf_detach(arg);
  return NULL; 
}

void *fips_buf_deinit_benchmark_process(void *arg) { 
  fips_buf_destroy(arg,0);
  return NULL; }

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
