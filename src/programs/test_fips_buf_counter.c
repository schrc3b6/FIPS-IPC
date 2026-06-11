#include <fips_buf.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>

#define NUM_THREADS 1
#define IOV_SIZE 10

struct args {
  fips_buf_arg_t *arg;
  int thread_id;
  uint64_t parsed_count;
};

sig_atomic_t stop = 0;


void *run_thread(void *arg) {
  struct args* argument = (struct args *)arg;
  fips_buf_thread_arg_t fips_buf_thread_arg = {0};
  fips_buf_thread_arg.process_arg = argument->arg;
  printf("attach %d\n", fips_buf_attach(&fips_buf_thread_arg));
  size_t read = 0;
  struct iovec iov[IOV_SIZE];
  uint64_t tag;
  #if  defined(YIELD_PRIO) || defined(SLEEP_PRIO)
  long sched_read = 0;
  #endif

  uint64_t tries = 0;
  do {
    int ret = fips_buf_read(&fips_buf_thread_arg, iov, IOV_SIZE, &tag, 0);
    if (ret != FIPS_BUF_SUCCESS) {
      #ifdef SLEEP
      nanosleep((const struct timespec[]){{0, 1000000L}}, NULL);
      #endif
      #ifdef SLEEP_PRIO
      nanosleep((const struct timespec[]){{0, 1000000000L - sched_read}}, NULL);
      sched_read=0;
      #endif
      #ifdef YIELD_PRIO
      if(sched_read < 5) {
        int prio=getpriority(PRIO_PROCESS, 0);
        setpriority(PRIO_PROCESS, 0, prio-1);
      }
      sched_read = 0;
      //sched_yield();
      #endif
      #ifdef YIELD
      sched_yield();
      #endif
      continue;
    }
    #ifdef YIELD_PRIO
    sched_read += 1;
    #endif
    #ifdef SLEEP_PRIO
    sched_read += 1000000L;
    #endif
    read += IOV_SIZE;
    ret = fips_buf_return(&fips_buf_thread_arg, tag);
    if (ret != FIPS_BUF_SUCCESS) {
      fprintf(stderr, "fips_buf_return failed: %d\n", ret);
    }
    #ifdef YIELD_PRIO
    if (sched_read > 100) {
      sched_read = 10;
      int prio=getpriority(PRIO_PROCESS, 0);
      setpriority(PRIO_PROCESS, 0, prio+1);
    }
    #endif
  } while (stop == 0);

  printf("read %ld\n", read);

  printf("detach %d\n", fips_buf_detach(&fips_buf_thread_arg));

  pthread_exit(NULL);
}

void signal_handler(int signum) {
  stop = 1;
}

int main(int argc, char *argv[]) {
  pthread_t threads[NUM_THREADS];
  struct args arguments[NUM_THREADS];
  int rc;
  long t;

  sigaction(SIGINT, &(struct sigaction){.sa_handler = signal_handler}, NULL);

  fips_buf_arg_t arg = {0};
        arg.role = FIPS_READER;
        // arg.shm_name = "/fips_zero_copy";
        // arg.line_size = 200;
        // arg.max_sqe_count = 1024;
        // arg.line_count_exp = 22;
        // arg.max_reader_count = 2;
        // arg.max_reader_thread_count = 17;
        // arg.max_segment_count = 17;
        // arg.flags = FIPS_BUF_FLAG_OVERWRITE;

  char *config_file = getenv("FIPS_BUF_CONF");
  if (config_file)
    printf("init %d\n", fips_buf_init(&arg, config_file));
  else
    printf("init %d\n", fips_buf_init(&arg, "/etc/fips_buf.conf"));
  for (t = 1; t < NUM_THREADS; t++) {
    arguments[t].arg = &arg;
    printf("Creating thread #%ld\n", t);
    rc = pthread_create(&threads[t], NULL, run_thread, &arguments[t]);
    if (rc) {
      printf("Error: unable to create thread, %d\n", rc);
      exit(-1);
    }
  }

  run_thread(arguments);

  // Wait for all threads to complete
  for (t = 1; t < NUM_THREADS; t++) {
    pthread_join(threads[t], NULL);
  }

  printf("destroy %d\n", fips_buf_destroy(&arg, 0));

  pthread_exit(NULL);
}
