#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>

#define LINE_SIZE 64
#define SEGMENT_COUNT 4 // not used anymore see benchmark_args.num_threads
#define LINE_COUNT_EXP 22 //not used anymore see benchmark_args.line_count_exp
#define STRING_SIZE 20
#define SHM_PATH "/test_shm"
#define IOVLEN 10

typedef void *(*init_benchmark_process)(void);
typedef void *(*init_benchmark_thread)(void *arg);
typedef void *(*read_benchmark)(void *arg);
typedef void *(*write_benchmark)(void *arg);
typedef void *(*deinit_benchmark_thread)(void *arg);
typedef void *(*deinit_benchmark_process)(void *arg);

typedef struct {
  init_benchmark_process init_process;
  init_benchmark_thread init_thread;
  read_benchmark read;
  write_benchmark write;
  deinit_benchmark_thread deinit_thread;
  deinit_benchmark_process deinit_process;
} benchmark_functions_t;

typedef struct {
  char *mode;
  long long operations;
  double limit;
  char *string_generator;
  int string_length;
  unsigned int num_threads;
  unsigned int wait_for;
  int line_count_exp;
  bool print_header;
  char *prog_name;
} Arguments;

union semun {
  int val;
  struct semid_ds *buf;
  unsigned short *array;
};

extern Arguments benchmark_args;
extern volatile sig_atomic_t stop;
extern __thread jmp_buf jmpbuf;

char *string_generator(int length);
static inline void handle_alarm(void) {
  if (stop)
    longjmp(jmpbuf, 1);
}
benchmark_functions_t register_benchmark(void);
