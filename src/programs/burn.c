#define MAX_THREADS 10
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <unistd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syslog.h>
#include <time.h>

#define NUMLOGS 1000000
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int use_affinity=1;

double timespec_diff_ms(struct timespec* start, struct timespec* end) {
    double start_ms = start->tv_sec * 1000.0 + start->tv_nsec / 1.0e6;
    double end_ms = end->tv_sec * 1000.0 + end->tv_nsec / 1.0e6;
    return end_ms - start_ms;
}

void *burn(void *arg){
  struct timespec s = {0,1};
  if (use_affinity){
    int* affinity = (int *)arg;
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(*affinity, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0){
      perror("sched_setaffinity");
      exit(1);
    }
  }
  struct timespec start = {0};
  struct timespec end = {0};
  clock_gettime(CLOCK_MONOTONIC, &start);
  for(long long i=0;i<NUMLOGS;i++){
    pthread_mutex_lock(&m);
    syslog(LOG_INFO,"hallo welt dies is ein %s.","string");
    // nanosleep(&s, NULL);
    pthread_mutex_unlock(&m);
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  printf("time: %lf\n", timespec_diff_ms(&start,&end));
  fflush(stdout);
  return NULL;
}

int main(int argc, char *argv[]){
  int threads = 1;
  int cpu_affinity[MAX_THREADS];

  openlog("burn",0,LOG_LOCAL0);

  
  if (argc > 1){
    threads = atoi(argv[1]);
  }
  if (argc == 2){
    use_affinity = 0;
  }
  for (int i = 2; i < argc; i++){
    cpu_affinity[i-2] = atoi(argv[i]);
  }
  pthread_t tid[threads-1];
  for (int i = 1; i < threads; i++){
    pthread_create(&tid[i-1], NULL, burn, cpu_affinity+i);
  }

  burn(cpu_affinity);

  for (int i = 1; i < threads; i++){
    pthread_join(tid[i-1], NULL);
  }
}
