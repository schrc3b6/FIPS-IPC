#define _GNU_SOURCE 1
#define _XOPEN_SOURCE
#include <fips_buf.h>
#include <hs/hs_common.h>
#include <hs_compile.h>
#include <shm_ringbuf.h>
#include <threads.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <hs.h>
#include <liburing.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
// #include <client_wrapper.h>
#ifdef GRPC
#include "client_wrapper.h"
#endif

// Local includes
#include <ebpf_utils.h>
#include <io_ipc.h>
#include <ip_hashtable.h>
#include <ip_llist.h>
#include <uring_getline.h>

#include "ip_blacklist.skel.h"
#define DEFAULT_BAN_TIME 30
#define DEFAULT_BAN_FINDTIME 30
#define DEFAULT_BAN_THRESHOLD 3
#define DEFAULT_THREAD_COUNT 1 // For multi-threading
#define DEFAULT_IPC_TYPE DISK
#define DEFAULT_IFACE "enp24s0f0np0"
#define DEFAULT_LOG "/mnt/scratch/signer/fips-ipc-bind/build/udpsvr.log"
// #define DEFAULT_MATCH_REGEX "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} client
// (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+) exceeded request
// rate limit" #define IP4_REGEX
// "((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)"
#define IP4_REGEX                                                              \
  "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(\\#)" //((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)(\\/))"
#define RATE_LIMIT_REGEX "client"
#define IP6_REGEX                                                              \
  "([a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-" \
  "f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4})|([a-f0-9:]{0,35}::[a-f0-9:]{0,35})" \
  "(\\#)"
#define LINEBUF_SIZE 200
#define NTHREADS 1
#define QUEUE_SIZE 100 // Number of entries read at once

// Hyperscan
#define DEFAULT_MATCH_REGEX_ID 0
#define IP4_REGEX_ID 1
#define IP6_REGEX_ID 2
#define RATE_LIMIT_REGEX_ID 3

// Return values
#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)

// Open options
#define OPEN_MODE O_RDONLY
#define OPEN_PERM 0644

#define DATE_FMT "%d-%b-%Y %H:%M:%S"

struct ipc_args_t;
typedef struct ipc_args_t ipc_args_t;

typedef struct config {
  enum ipc_type_t ipc_type;
  uint8_t thread_count;
  uint16_t bantime;
  uint16_t limit;
  uint16_t findtime;
  bool matching, verbose;
  bool wload_stealing;
  int bpf_nr_cpus;
  char *shm_key;
  char *logfile;
  char *regex;
  char *regex_rate_limit;
  char *interface;
  struct in_addr whitelistv4;
  struct in6_addr whitelistv6;
} config_t;

typedef struct server {
  // this needs to stay first member of the struct
  // to allow for easy casting to config_t
  config_t config;

  // server state
  volatile sig_atomic_t server_running;
  pthread_mutex_t stdout_lock;
  pthread_mutex_t stderr_lock;
  struct ip_hashtable_t *htable;
  struct ip_llist_t *banned_list;
  hs_database_t *database;

  // TODO: For what?
  int ipv4_ebpf_map;
  int ipv6_ebpf_map;
} server_t;

// global variables
extern server_t server;

// Timeout value for unbanning thread
#define NANOSECONDS_PER_MILLISECOND 1000000
#define TIMEOUT 200 * NANOSECONDS_PER_MILLISECOND

// Helpers
#define UNUSED(x) ((void)x)

// Structs

// Parameters for unbanning thread
struct unban_targs_t {
  uint32_t wakeup_interval;
  uint64_t unban_count;
  int retval;
};

// Binary ip address representation
union ip_addr_t {
  uint32_t ipv4;
  __uint128_t ipv6;
};

struct hs_context_t {
  int domain;
  bool match;
  bool rate_limit_match;
  char *logstr;
  union ip_addr_t ip_addr;
  regex_t *regex;
  unsigned int from;
  time_t timestamp;
};

// Parameters for banning threads
struct ban_targs_t {
  void *ipc_args;
  uint8_t thread_id;
  uint32_t wakeup_interval;
  uint64_t rcv_count;
  uint64_t ban_count;
  uint64_t too_old;
  uint64_t steal_count;
  char strerror_buf[64];
  int retval;
  fips_buf_arg_t *arg;
};

// Struct passed to arg_parse
struct arguments {
  bool ipc_set;
  char *grpc_ip;
};

int init_ipc(struct ban_targs_t *thread_args);

int init_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t ** ipc_thread_arg);

int deinit_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg);

int get_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs);

int return_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs);

bool cleanup_ipc(struct ban_targs_t **thread_args);

int init_grpc();

int init_hs(void);

void *unban_thread_routine(void *args);

int regex_match_handler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx);

void *ban_thread_routine(void *args);

void sync_message(const char *fmt, pthread_mutex_t *lock, FILE *fp,
                  va_list targs);

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char *fmt, ...);

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char *fmt, ...);

void sig_handler(int signal);

int8_t block_signals(bool keep);

bool is_whitelistv4(uint32_t address, uint32_t subnet, uint8_t subnet_size);
