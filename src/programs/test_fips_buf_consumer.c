#include <fips_buf.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM_THREADS 16

struct args {
  fips_buf_arg_t *arg;
  int thread_id;
  uint64_t parsed_count;
};


void *run_thread(void *arg) {
  struct args* argument = (struct args *)arg;
  fips_buf_thread_arg_t fips_buf_thread_arg = {0};
  fips_buf_thread_arg.process_arg = argument->arg;
  printf("attach %d\n", fips_buf_attach(&fips_buf_thread_arg));
  size_t read = 0;
  struct iovec iov[10];
  uint64_t tag;

  uint64_t tries = 0;
  do {
    int ret = fips_buf_read(&fips_buf_thread_arg, iov, 10, &tag, 0);
    if (ret != FIPS_BUF_SUCCESS) {
      fprintf(stderr, "fips_buf_read failed: %d segment %d \n", ret, fips_buf_thread_arg.assignment->start_segment);
      fflush(stderr);
      continue;
    }
    read += 10;
    ret = fips_buf_return(&fips_buf_thread_arg, tag);
    if (ret != FIPS_BUF_SUCCESS) {
      fprintf(stderr, "fips_buf_return failed: %d\n", ret);
    }
    printf("read %ld\n", read);
    tries++;
  } while (tries<1E7);

  printf("detach %d\n", fips_buf_detach(&fips_buf_thread_arg));

  pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
  pthread_t threads[NUM_THREADS];
  struct args arguments[NUM_THREADS];
  int rc;
  long t;


  fips_buf_arg_t arg = {0};
  arg.role = FIPS_READER;
  // arg.shm_name = "/test_shm";
  // arg.line_size = 64;
  // arg.max_sqe_count = 1024;
  // arg.line_count_exp = 12;
  // arg.max_reader_count = 4;
  // arg.max_reader_thread_count = 32;
  // arg.max_segment_count = 32;

  char *config_file = getenv("FIPS_BUF_CONF");
  if (config_file)
    printf("init %d\n", fips_buf_init(&arg, config_file));
  else
    printf("init %d\n", fips_buf_init(&arg, "/etc/fips_buf.conf"));

  for (t = 0; t < NUM_THREADS; t++) {
    arguments[t].arg = &arg;
    printf("Creating thread #%ld\n", t);
    rc = pthread_create(&threads[t], NULL, run_thread, &arguments[t]);
    if (rc) {
      printf("Error: unable to create thread, %d\n", rc);
      exit(-1);
    }
  }

  // Wait for all threads to complete
  for (t = 0; t < NUM_THREADS; t++) {
    pthread_join(threads[t], NULL);
  }

  printf("destroy %d\n", fips_buf_destroy(&arg, 0));

  pthread_exit(NULL);
}
