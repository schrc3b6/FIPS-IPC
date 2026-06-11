#include "benchmark.h"
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>
#include <errno.h>

#include <time.h>

#define BENCHMARK_SEM_INIT_PATH "/tmp/benchmark_init_sem"

Arguments parse_arguments(int argc, char *argv[]) {
  Arguments args;
  args.prog_name= *argv;
  args.print_header=false;
  args.limit = -1.0; // default value for optional argument
  char *usage = "Usage: %s -m mode -o operations [-l limit] -s "
                "string_generator -n string_length -t num_threads [-w "
                "number_of_processes_to_wait_for] -e line_count_exp -h \n";

  int opt;
  while ((opt = getopt(argc, argv, "m:o:l:s:n:t:w:e:h")) != -1) {
    switch (opt) {
    case 'm':
      args.mode = optarg;
      break;
    case 'o':
      args.operations = atoi(optarg);
      break;
    case 'l':
      args.limit = atof(optarg);
      break;
    case 's':
      args.string_generator = optarg;
      break;
    case 'n':
      args.string_length = atoi(optarg);
      break;
    case 't':
      args.num_threads = atoi(optarg);
      break;
    case 'w':
      args.wait_for = atoi(optarg);
      break;
    case 'e':
      args.line_count_exp = atoi(optarg);
      break;
    case 'h':
      args.print_header = true;
      break;
    default:
      fprintf(stderr, usage, argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (args.mode == NULL || args.operations == 0 ||
      args.string_generator == NULL || args.string_length == 0 ||
      args.num_threads == 0 || args.line_count_exp == 0) {
    fprintf(stderr, usage, argv[0]);
    exit(EXIT_FAILURE);
  }

  if (strcmp(args.mode, "reader") && strcmp(args.mode, "writer")) {
    fprintf(stderr, "Invalid mode! write or read\n");
    exit(EXIT_FAILURE);
  }

  return args;
}

char *string_generator(int length) {
  // we currently do not need different strings so we can just return a static
  // string
  return "Hello World!";
}

benchmark_functions_t functions;
pthread_barrier_t barrier;
pthread_barrier_t barrier_fin;
Arguments benchmark_args;
volatile sig_atomic_t stop = 0;
__thread jmp_buf jmpbuf;

void *benchmark_thread(void *arg) {
  void *process_arg = arg;
  void *thread_arg = functions.init_thread(process_arg);

  uintptr_t i = 0;

  pthread_barrier_wait(&barrier);

  setjmp(jmpbuf);
  if (!strcmp(benchmark_args.mode, "reader")) {
    for (i = 0; i < benchmark_args.operations && !stop; i++) {
      functions.read(thread_arg);
    }
  } else if (!strcmp(benchmark_args.mode, "writer")) {
    for (i = 0; i < benchmark_args.operations && !stop; i++) {
      functions.write(thread_arg);
    }
  } else {
    fprintf(stderr, "Invalid mode! write or read\n");
    exit(EXIT_FAILURE);
  }

  pthread_barrier_wait(&barrier_fin);

  functions.deinit_thread(thread_arg);
  return (void *)i;
}

void handle_signal(int signal) { stop = 1; }

int wait_for_processes(int num_processes) {

  if (access(BENCHMARK_SEM_INIT_PATH, F_OK) == -1) {
    if (fopen(BENCHMARK_SEM_INIT_PATH, "w") == NULL) {
      fprintf(stderr, "Failed to create semaphore file\n");
      return -1;
    }
  }
  key_t key = ftok(BENCHMARK_SEM_INIT_PATH, 65);
  if (key == -1) {
    perror("ftok");
    return -1;
  }

  union semun semarg;
  int semid = semget(key, 1, 0666 | IPC_CREAT | IPC_EXCL);
  if (semid == -1) {
    if (errno == EEXIST) {
      semid = semget(key, 1, 0666);
      if (semid == -1) {
        perror("semget");
        return -1;
      }
    } else {
      perror("semget");
      return -1;
    }
  } else {
    // initialize semaphore
    semarg.val = 0;
    if (semctl(semid, 0, SETVAL, semarg) == -1) {
      perror("semctl");
      return -1;
    }
  }
  int waiting_procs = semctl(semid, 0, GETNCNT);
  if (waiting_procs == -1) {
    perror("semctl");
    return -1;
  }

  if (waiting_procs < num_processes -1) {
    // we need to wait for other processes
    struct sembuf sem_lock = {0, -1, 0};
    if(semop(semid, &sem_lock, 1)== -1){
      perror("semop");
      return -1;
    }
  } else {
    // we are the last process, we need to unlock the semaphore
    struct sembuf sem_unlock = {0, num_processes - 1, 0};
    if(semop(semid, &sem_unlock, 1)){
      perror("semop");
      return -1;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  benchmark_args = parse_arguments(argc, argv);

  functions = register_benchmark();

  if(benchmark_args.wait_for > 0){
    if(wait_for_processes(benchmark_args.wait_for) == -1){
      fprintf(stderr, "Failed to wait for other processes\n");
      exit(EXIT_FAILURE);
    }
    if(strcmp(benchmark_args.mode, "writer")){
      nanosleep((const struct timespec[]){{0, 100000L}}, NULL);
    }
  }

  if (benchmark_args.limit > 0) {
    signal(SIGALRM, handle_signal);
    alarm(benchmark_args.limit);
  }

  void *process_arg = functions.init_process();
  if (process_arg == NULL) {
    fprintf(stderr, "Failed to initialize process\n");
    exit(EXIT_FAILURE);
  }

  pthread_t *threads = calloc(benchmark_args.num_threads, sizeof(pthread_t));
  pthread_barrier_init(&barrier_fin, NULL,
                       benchmark_args.num_threads + 1); // FIXME: error handling
  pthread_barrier_init(&barrier, NULL,
                       benchmark_args.num_threads + 1); // FIXME: error handling
  for (int i = 0; i < benchmark_args.num_threads; i++) {
    int state =
        pthread_create(&threads[i], NULL, benchmark_thread, process_arg);
    if (state != 0) {
      fprintf(stderr, "Failed to create thread\n");
      break;
    }
  }

  pthread_barrier_wait(&barrier);
  // start measuring time
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  pthread_barrier_wait(&barrier_fin);
  clock_gettime(CLOCK_MONOTONIC, &end);

  unsigned long long elapsed_ns =
      (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);

  // join all started threads
  uintptr_t total_operations = 0;
  uintptr_t thread_operations = 0;
  for (int i = 0; i < benchmark_args.num_threads; i++) {
    if (threads[i] != 0) {
      pthread_join(threads[i], (void **)&thread_operations);
      total_operations += thread_operations;
    }
  }

  if (benchmark_args.print_header)
  fprintf(stdout, "prog_name;mode;num_threads;line_count_exp;operations;total_operations;time\n");
  fprintf(stdout, "%s;%s;%u;%d;%lld;%lu;%lf\n",benchmark_args.prog_name,benchmark_args.mode,benchmark_args.num_threads,benchmark_args.line_count_exp,benchmark_args.operations,total_operations,elapsed_ns/1E9F);

  //fprintf(stdout, "Total operations: %lu in %lf s\n", total_operations, elapsed_ns/1E9F);

  pthread_barrier_destroy(&barrier);
  pthread_barrier_destroy(&barrier_fin);
  functions.deinit_process(process_arg);
}
