#define _GNU_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

// Local includes
#include <fips_buf.h>
#include <io_ipc.h>
#include <ip_to_str.h>
#include <shm_ringbuf.h>

// Definitions

// Default configuration
#define DEFAULT_PORT 8080
#define DEFAULT_LOG "udpsvr.log"
#define LOG_SHORT false
#define BINARY false
#define IPC_TYPE DISK
#define NTHREADS 1

// Shared memory default configuration
#define SHM_NLINES 100000
#define NREADERS 1

// Open options for logfile
#define OPEN_MODE O_WRONLY | O_CREAT | O_TRUNC | O_APPEND
#define OPEN_PERM 0644

// Return codes
#define RETURN_SUC (0)
#define RETURN_FAIL (-1)

// Logstring stuff
//13-May-2025 09:21:59
#define DATE_FMT "DD-MMM-YYYY HH:MM:SS"
// #define STRFTIME_FMT "%Y-%m-%d %H:%M:%S"
#define STRFTIME_FMT "%d-%b-%Y %H:%M:%S"
// #define DATE_FMT "%d-%b-%Y %H:%M:%S"
#define DATE_SIZE (sizeof(DATE_FMT) - 1)
#define STR_SIZE_IP4 (sizeof("DDD.DDD.DDD.DDD") - 1)
#define STR_SIZE_IP6 (sizeof("DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD") - 1)
#define LOG_STR_FMT_IP4                                                        \
  "YYYY-MM-DD HH:MM:SS client DDD.DDD.DDD.DDD exceeded request rate limit\n"
#define LOG_BUF_SIZE_IP4 (sizeof(LOG_STR_FMT_IP4) - 1)
#define LOG_STR_FMT_IP6                                                        \
  "YYYY-MM-DD HH:MM:SS client DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD "        \
  "exceeded request rate limit\n"
#define LOG_BUF_SIZE_IP6 (sizeof(LOG_STR_FMT_IP6) - 1)
#define HOST_PREFIX " client "
#define HOST_PREFIX_SIZE (sizeof(HOST_PREFIX) - 1)
#define MSG_STR " exceeded request rate limit\n"
#define MSG_STR_SIZE (sizeof(MSG_STR) - 1)

// Characters
#define NEWLINE_CHAR (char)(10)
#define BLANK (char)(32)
#define INVALID_PAYLOAD ('B')

// Sizes
#define NANOSECONDS_PER_MILLISECOND 1000000
#define MICROSECONDS_PER_MILISECOND 1000
#define UTIL_TIMEOUT                                                           \
  500 * NANOSECONDS_PER_MILLISECOND // Timeout for background thread
#define RECV_TIMEOUT                                                           \
  MICROSECONDS_PER_MILISECOND * 100 // Timeout for receiving sockets
#define MAX_MSG __IOV_MAX // Size of receive and send queue for sockets

// Helpers
#define UNUSED(x) (void)(x)

// Global Variables
static char global_datetime_buf[DATE_SIZE + 1];
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t datebuf_lock = PTHREAD_RWLOCK_INITIALIZER;
static enum ipc_type_t ipc_type = IPC_TYPE;
static in_port_t port = DEFAULT_PORT;
static bool logshort = LOG_SHORT;
static bool binary = BINARY;
static uint8_t thread_count = NTHREADS;

// Structs

// Send / Receive buffers for listener threads
struct packet_buf_t {
  struct mmsghdr msgs[MAX_MSG];
  struct iovec iovecs[MAX_MSG];
  unsigned char payload_buf[MAX_MSG];
};

// Logfile writing parameters
struct disk_arg_t {
  int logfile_fd;
  struct io_uring ring;
};

// Parameters for listener threads
struct sock_targ_t {
  uint8_t thread_id;
  void *ipc_arg;
  uint64_t pkt_in;
  uint64_t pkt_out;
  uint64_t log_count;
  uint64_t log_drop;
  char strerror_buf[64];
  int domain;
  int return_code;
};

// Paramters for utility thread
struct util_targ_t {
  size_t interval;
  int return_code;
};

// Argparse

const char *argp_program_version = "Simple UDP Server";

// Command line options for the program
static struct argp_option options[] = {
    {"file", 'f', "LOGFILE", OPTION_ARG_OPTIONAL, "Specify logfile as ipc type",
     0},
    {"posix", 'x', "LOGFILE", OPTION_ARG_OPTIONAL, "Specify logfile as ipc type",
     0},
    {"threads", 't', "N", OPTION_ARG_OPTIONAL,
     "Specify the number of listener threads to use", 0},
    {"logshort", 'l', NULL, 0,
     "Enable short logging (will only log a clients IP address)", 0},
    {"shm", 's', "KEY", OPTION_ARG_OPTIONAL,
     "Specify shared memory as ipc type", 0},
    {"fips", 'z', NULL, 0, "Specify FIPS as ipc type", 0},
    {"binary", 'b', NULL, 0, "Specify FIPS as ipc type", 0},
    {"nlines", 'n', "NUM", 0,
     "Specify number of lines per segment for shared memory", 0},
    {"nreaders", 'r', "N", 0, "Specify max number of readers for shared memory",
     0},
    {"overwrite", 'o', NULL, 0, "Enable overwrite for shared memory", 0},
    {"port", 'p', "PORT", 0, "Specify the port to listen at", 0},
    {0}};

// Struct passed to argument parser
struct arguments {
  bool ipc_set;
  char *logfile;
  char *shm_key;
  uint16_t shm_line_size;
  uint32_t shm_lines;
  uint8_t shm_reader_count;
  bool overwrite;
  in_port_t ipc_port;
};

// Argument parser for command line arguments
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  struct stat statbuf;

  switch (key) {

  case 'x':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one ipc type allowed\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    ipc_type = POSIX_IO;

    if (arg) {
      arguments->logfile = arg;
    }

    break;

  case 'f':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one ipc type allowed\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    ipc_type = DISK;

    if (arg) {
      arguments->logfile = arg;
    }

    break;

  case 't':

    if (arg) {
      thread_count = (uint8_t)strtol(arg, NULL, 10);

      if (get_nprocs() < thread_count) {
        thread_count = get_nprocs();
        fprintf(stderr, "Using maximum number of listener threads = %d\n",
                thread_count);
      }

      if (thread_count == 0) {
        thread_count = 1;
        fprintf(stderr, "Minimum 1 listener thread required\n");
      }
    }

    else {
      thread_count = get_nprocs();
    }

    break;

  case 'b':

    binary = true;
    break;

  case 'l':

    logshort = true;
    break;

  case 'z':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one ipc type allowed\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    ipc_type = FIPS;

    break;

  case 's':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one IP type allowed\n");
      argp_usage(state);
    }

    if (arg) {
      if (stat(arg, &statbuf) != 0) {
        fprintf(stderr, "%s is not a valid filepath\n", arg);
        argp_usage(state);
      }
      arguments->shm_key = arg;
    }

    else {
      arguments->shm_key = DEFAULT_LOG;
    }

    arguments->ipc_set = true;
    ipc_type = SHM;

    break;

  case 'n':

    arguments->shm_lines = (uint32_t)strtol(arg, NULL, 10);

    if (arguments->shm_lines < 2) {
      fprintf(stderr, "Number of lines should be at least 2\n");
      arguments->shm_lines = 2;
    }

    break;

  case 'r':

    arguments->shm_reader_count = (uint8_t)strtol(arg, NULL, 10);

    if (arguments->shm_reader_count == 0) {
      fprintf(stderr, "Reader count has to be at least 1\n");
      arguments->shm_reader_count = 1;
    }

    break;

  case 'o':

    arguments->overwrite = true;

    break;

  case 'p':

    port = (in_port_t)strtol(arg, NULL, 10);

    if (port < 1023) {
      fprintf(stderr, "Invalid Port %d, using default port %d\n", port,
              DEFAULT_PORT);
      port = DEFAULT_PORT;
    }

    break;

  case ARGP_KEY_ARG:
    return 0;
  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = "A minimal udp server for testing IPC based logging implementations "
           "for Host Intrusion Detection Systems"};

// Helper functions

/* Prints a formatted string to a mutex locked file descriptor */
void synced_message(const char *fmt, pthread_mutex_t *lock, FILE *fp,
                    va_list targs) {
  pthread_mutex_lock(lock);
  vfprintf(fp, fmt, targs);
  pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char *fmt, ...) {
  va_list targs;
  va_start(targs, fmt);
  synced_message(fmt, &stdout_lock, stdout, targs);
  va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char *fmt, ...) {
  va_list targs;
  va_start(targs, fmt);
  synced_message(fmt, &stderr_lock, stderr, targs);
  va_end(targs);
}

/* Updates a datetime buffer with the formatted current datetime and returns a
 * timestamp */
time_t update_datetime(char *datebuf) {
  struct tm tm;
  time_t t = time(NULL);
  localtime_r(&t, &tm);
  pthread_rwlock_wrlock(&datebuf_lock);
  strftime(datebuf, DATE_SIZE + 1, STRFTIME_FMT, &tm);
  pthread_rwlock_unlock(&datebuf_lock);
  return t;
}

/* Blocks all blockable signals with the option to keep SIGINT and SIGTERM
 * unblocked */
int8_t block_signals(bool keep) {
  sigset_t set;

  if (sigfillset(&set)) {
    return RETURN_FAIL;
  }

  if (keep) {
    if (sigdelset(&set, SIGINT) || sigdelset(&set, SIGTERM)) {
      return RETURN_FAIL;
    }
  }

  if (pthread_sigmask(SIG_BLOCK, &set, NULL)) {
    return RETURN_FAIL;
  }

  return RETURN_SUC;
}

/* Handler for SIGINT and SIGTERM, sets the global variable server_running to
 * false */
void sig_handler(int signal) {
  UNUSED(signal);
  server_running = false;
}

/* Routine for helper thread to periodically wake up and update the
 global datetime buffer and handle user interrupts */
void *util_thread_routine(void *arg) {

  if (block_signals(true)) {
    error_msg("Failed to block signals\n");
  }
  if (signal(SIGINT, sig_handler) == SIG_ERR ||
      signal(SIGTERM, sig_handler) == SIG_ERR) {
    char strerror_buf[64];
    error_msg("Failed to set signal handler : %s\n",
              strerror_r(errno, strerror_buf, 64));
  }

  struct util_targ_t *targs = (struct util_targ_t *)arg;
  struct timespec ts = {.tv_nsec = targs->interval};

  while (server_running) {
    if (update_datetime(global_datetime_buf) == -1) {
      error_msg("Failed to updated datetime buffer\n");
    }

    nanosleep(&ts, NULL);
  }

  targs->return_code = RETURN_SUC;
  return &targs->return_code;
}

/* Copies the string form of the provided ip address [addr] to [logstr_buf] */
uint16_t logstr_bin_short(fips_bin_message_t *logstr_buf,
                          struct in6_addr *addr) {
  uint16_t addrlen;

  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    logstr_buf->address_len = 4;
    logstr_buf->address4 = *(uint32_t *)((char *)addr + 12);
  } else {
    logstr_buf->address_len = 16;
    logstr_buf->address6 = *(__uint128_t *)addr;
  }
  return 0;
}

/* Writes a logstring to logstr_addr */
uint16_t logstr_bin_long(fips_bin_message_t *logstr_buf,
                         struct in6_addr *addr) {

  time(&logstr_buf->timestamp);

  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    logstr_buf->address_len = 4;
    logstr_buf->address4 = *(uint32_t *)((char *)addr + 12);
  } else {
    logstr_buf->address_len = 16;
    logstr_buf->address6 = *(__uint128_t *)addr;
  }

  return 0;
}

/* Copies the string form of the provided ip address [addr] to [logstr_buf] */
uint16_t logstr_short(char *logstr_buf, struct in6_addr *addr) {
  uint16_t addrlen;

  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    addrlen = ipv4_to_str((uint32_t *)((char *)addr + 12), logstr_buf);
  } else {
    addrlen = ipv6_to_str((__uint128_t *)addr, logstr_buf);
  }

  logstr_buf[addrlen] = NEWLINE_CHAR;
  return addrlen + 1;
}

/* Writes a logstring to logstr_addr */
uint16_t logstr_long(char *logstr_buf, struct in6_addr *addr) {
  uint16_t offset = 0;

  pthread_rwlock_rdlock(&datebuf_lock);
  if (memcpy(logstr_buf, global_datetime_buf, DATE_SIZE) == NULL) {
    pthread_rwlock_unlock(&datebuf_lock);
    return 0;
  }
  pthread_rwlock_unlock(&datebuf_lock);

  offset += DATE_SIZE;

  if (memcpy(logstr_buf + offset, HOST_PREFIX, HOST_PREFIX_SIZE) == NULL) {
    return 0;
  }

  offset += HOST_PREFIX_SIZE;

  if (IN6_IS_ADDR_V4MAPPED(addr)) {
    offset +=
        ipv4_to_str((uint32_t *)((char *)addr + 12), (logstr_buf + offset));
  } else {
    offset += ipv6_to_str((__uint128_t *)addr, (logstr_buf + offset));
  }
  logstr_buf[offset]='#';
  offset++;

  if (memcpy(logstr_buf + offset, MSG_STR, MSG_STR_SIZE) == NULL) {
    return 0;
  }

  return offset + MSG_STR_SIZE;
}

/* Frees all memory allocated in the listen and reply function and copies
 * counter values to thread arg*/
void cleanup_listen_and_reply(
    struct mmsghdr **msg_hdrs, struct iovec **snd_rcv_iovs,
    struct iovec **log_iovs, struct sockaddr_in6 **ip_buf,
    unsigned char **payload_buf, char **logstr_buf, struct sock_targ_t *targs,
    uint64_t pkt_in, uint64_t pkt_out, uint64_t msg_out, uint64_t msg_drop) {
  free(*msg_hdrs);
  free(*snd_rcv_iovs);
  free(*logstr_buf);
  free(*payload_buf);
  free(*log_iovs);
  free(*ip_buf);
  *msg_hdrs = NULL;
  *snd_rcv_iovs = NULL;
  *logstr_buf = NULL;
  *payload_buf = NULL;
  *log_iovs = NULL;
  *ip_buf = NULL;

  targs->pkt_in = pkt_in;
  targs->pkt_out = pkt_out;
  targs->log_count = msg_out;
  targs->log_drop = msg_drop;
}

/* Listen for incoming udp packets and replies. Invalid requests (First Byte of
 * Payload == B) are logged using ipc method specified by global ipy_type */
int listen_and_reply(int sockfd, struct sock_targ_t *targs) {

  struct mmsghdr *msg_hdrs = NULL;
  struct iovec *snd_rcv_iovs = NULL, *log_iovs = NULL;
  unsigned char *payload_buf = NULL;
  struct sockaddr_in6 *ip_buf = NULL;
  char *logstr_buf = NULL;
  fips_bin_message_t *logstr_bin_buf = NULL;
  int logfile_fd = -1, retval_rcv, retval_snd, retval_ipc, i, logbuf_size,
      invalid_count = 0;
  uint64_t pkt_in = 0, pkt_out = 0, msg_out = 0, msg_drop = 0;
  uint16_t logstr_len;
  uint8_t segment_id = targs->thread_id;
  struct io_uring *ring = NULL;
  struct io_uring_sqe *sqe = NULL;
  struct io_uring_cqe *cqe = NULL;
  struct shmrbuf_writer_arg_t *rbuf_arg = NULL;
  FILE *logfile_fp = NULL;
  fips_buf_thread_arg_t fips_buf_thread_arg = {0};

  switch (ipc_type) {
  case POSIX_IO:
    logfile_fp = targs->ipc_arg;
    break;
  case DISK:

    logfile_fd = ((struct disk_arg_t *)targs->ipc_arg)->logfile_fd;
    ring = &((struct disk_arg_t *)targs->ipc_arg)->ring;
    break;

  case SHM:

    rbuf_arg = (struct shmrbuf_writer_arg_t *)targs->ipc_arg;

    break;

  case FIPS:

    fips_buf_thread_arg.process_arg = (fips_buf_arg_t *)targs->ipc_arg;
    int ret = fips_buf_attach(&fips_buf_thread_arg);
    if (ret != FIPS_BUF_SUCCESS) {
      error_msg("Failed to attach to FIPS buffer\n");
      return RETURN_FAIL;
    }
    break;

  default:
    break;
  }

  logbuf_size = (logshort) ? (STR_SIZE_IP6 + 1) : LOG_BUF_SIZE_IP6;

  if ((msg_hdrs = (struct mmsghdr *)calloc(MAX_MSG, sizeof(struct mmsghdr))) ==
          NULL ||
      (snd_rcv_iovs = (struct iovec *)calloc(MAX_MSG, sizeof(struct iovec))) ==
          NULL ||
      (log_iovs = (struct iovec *)calloc(MAX_MSG, sizeof(struct iovec))) ==
          NULL ||
      (payload_buf = (unsigned char *)calloc(MAX_MSG, sizeof(unsigned char))) ==
          NULL ||
      (logstr_buf = (char *)calloc(MAX_MSG, logbuf_size)) == NULL ||
      (logstr_bin_buf = (fips_bin_message_t *)calloc(
           MAX_MSG, sizeof(fips_bin_message_t))) == NULL ||
      (ip_buf = (struct sockaddr_in6 *)calloc(
           MAX_MSG, sizeof(struct sockaddr_in6))) == NULL) {
    error_msg(
        "Memory allocation failed : %s",
        strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
    cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                             &payload_buf, &logstr_buf, targs, pkt_in, pkt_out,
                             msg_out, msg_drop);
    return RETURN_FAIL;
  }

  // redundant due to calloc
  if (memset(msg_hdrs, 0, sizeof(struct mmsghdr) * MAX_MSG) == NULL) {
    error_msg("Memset error\n");
  }

  for (i = 0; i < MAX_MSG; i++) {
    snd_rcv_iovs[i].iov_base = &payload_buf[i];
    snd_rcv_iovs[i].iov_len = 1;
    msg_hdrs[i].msg_hdr.msg_iov = &snd_rcv_iovs[i];
    msg_hdrs[i].msg_hdr.msg_iovlen = 1;
    msg_hdrs[i].msg_hdr.msg_name = (void *)(ip_buf + i);
    msg_hdrs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
  }

  int available_iovs = 0;

  while (server_running) {

    // printf("before recv \n");
    //MSG_WAITALL
    retval_rcv = recvmmsg(sockfd, msg_hdrs, MAX_MSG, MSG_WAITALL , NULL);
    // retval_rcv = recv(sockfd,msg_hdrs->msg_hdr.msg_iov[0].iov_base,msg_hdrs->msg_hdr.msg_iov[0].iov_len, 0);
    
    if (retval_rcv == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        // perror("receive");
        continue;
      } else {
        error_msg("Error in recvmmsg : %s\n",
                  strerror_r(errno, targs->strerror_buf,
                             sizeof(targs->strerror_buf)));
        cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                                 &payload_buf, &logstr_buf, targs, pkt_in,
                                 pkt_out, msg_out, msg_drop);
        return RETURN_FAIL;
      }
    }

    // fprintf(stderr, "received %d\n", retval_rcv);
    // fflush(stderr);
    pkt_in += retval_rcv;

    // If ipc_type is DISK, check if previous io_uring submission was successful
    if (ipc_type == DISK && sqe != NULL) {
      sqe = NULL;

      if (((retval_ipc = io_uring_wait_cqe(ring, &cqe)) < 0) ||
          (cqe->res < 0)) {
        error_msg("Error in io_uring write : %s\n",
                  strerror_r(errno, targs->strerror_buf,
                             sizeof(targs->strerror_buf)));
        cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                                 &payload_buf, &logstr_buf, targs, pkt_in,
                                 pkt_out, msg_out, msg_drop);
        return RETURN_FAIL;
      }

      io_uring_cqe_seen(ring, cqe);
    }


    uint32_t logstr_index = 0;

    for (i = 0; i < retval_rcv; i++) {

      // if (payload_buf[i] == INVALID_PAYLOAD) {

        if (ipc_type == FIPS && available_iovs < 1) {
          fips_get_write_buffer(&fips_buf_thread_arg, log_iovs, MAX_MSG);
          available_iovs = MAX_MSG;
          logstr_index =0;
          // fprintf(stderr,"get_write_buffer %d\n", available_iovs);
        }
        if (binary) {
          int res;
          if (logshort) {
            res = logstr_bin_short(
                log_iovs[logstr_index].iov_base,
                &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                     ->sin6_addr);
          } else {
            res = logstr_bin_long(
                log_iovs[logstr_index].iov_base,
                &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                     ->sin6_addr);
          }
          if (res == 0) {
            log_iovs[invalid_count].iov_len = sizeof(fips_bin_message_t);
            logstr_index += 1;
            available_iovs--;
            invalid_count++;
          } else {
            error_msg("Error writing binary logstring\n");
          }
        } else {
          if(ipc_type == FIPS){

            if (logshort) {
              logstr_len = logstr_short(
                  log_iovs[logstr_index].iov_base, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            } else {
              logstr_len = logstr_long(
                  log_iovs[logstr_index].iov_base, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            }
            if (logstr_len > 0) {
              log_iovs[logstr_index].iov_len = logstr_len;
              logstr_index += 1;
              available_iovs--;
              invalid_count++;
            }
            else {
              error_msg("Error writing logstring\n");
            }

          }else{
          if (ipc_type == POSIX_IO) {

            char *logstr = &logstr_buf[logstr_index];

            if (logshort) {
              logstr_len = logstr_short(
                  logstr, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            } else {
              logstr_len = logstr_long(
                  logstr, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            }
            invalid_count++;
            // pthread_mutex_lock(&log_lock);
            logstr[logstr_len]=0;
            fprintf(logfile_fp, "%s", logstr);
            // pthread_mutex_unlock(&log_lock);

          }else{

            char *logstr = &logstr_buf[logstr_index];

            if (logshort) {
              logstr_len = logstr_short(
                  logstr, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            } else {
              logstr_len = logstr_long(
                  logstr, &((struct sockaddr_in6 *)msg_hdrs[i].msg_hdr.msg_name)
                               ->sin6_addr);
            }

            if (logstr_len > 0) {
              log_iovs[invalid_count].iov_base = (void *)logstr;
              log_iovs[invalid_count].iov_len = logstr_len;
              available_iovs--;
              logstr_index += logbuf_size;
              invalid_count++;
            }
            else {
              error_msg("Error writing logstring\n");
            }
          }}
        }
        if (ipc_type == FIPS && available_iovs < 1) {
          fips_buf_write(&fips_buf_thread_arg, log_iovs, MAX_MSG);
        }
      // }

      // payload_buf[i] = payload_buf[i] + 1; // this doesn't look right, i just needs to be incremented
    }

    // fprintf(stderr, "logging %d messages\n", invalid_count);
    if (invalid_count) {

      switch (ipc_type) {
      case DISK:

        sqe = io_uring_get_sqe(ring);

        io_uring_prep_writev(sqe, logfile_fd, log_iovs, invalid_count, -1);

        if (io_uring_submit(ring) == -1) {
          error_msg("Error in io_uring submit : %s\n",
                    strerror_r(errno, targs->strerror_buf,
                               sizeof(targs->strerror_buf)));
          cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                                   &payload_buf, &logstr_buf, targs, pkt_in,
                                   pkt_out, msg_out, msg_drop);
          targs->log_drop += invalid_count;
          return RETURN_FAIL;
        }

        break;

      case SHM:

        if ((retval_ipc = shmrbuf_writev(rbuf_arg, log_iovs, invalid_count,
                                         segment_id)) < 0) {
          error_msg("Error in shmrbuf_writev : error code %d\n", retval_ipc);
          cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                                   &payload_buf, &logstr_buf, targs, pkt_in,
                                   pkt_out, msg_out, msg_drop);
          targs->log_drop += invalid_count;
          return RETURN_FAIL;
        }

        else if (retval_ipc < invalid_count) {
          msg_drop += invalid_count - retval_ipc;
          invalid_count = retval_ipc;
        }

        break;

      default:
        break;
      }

      msg_out += invalid_count;
      invalid_count = 0;
    }

    if ((retval_snd = sendmmsg(sockfd, msg_hdrs, retval_rcv, 0)) == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
          errno != ECONNREFUSED) {
        error_msg("Error in sendmmsg : %s\n",
                  strerror_r(errno, targs->strerror_buf,
                             sizeof(targs->strerror_buf)));
        cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                                 &payload_buf, &logstr_buf, targs, pkt_in,
                                 pkt_out, msg_out, msg_drop);
        return RETURN_FAIL;
      }
    } else {
      pkt_out += retval_snd;
    }
  }

  cleanup_listen_and_reply(&msg_hdrs, &snd_rcv_iovs, &log_iovs, &ip_buf,
                           &payload_buf, &logstr_buf, targs, pkt_in, pkt_out,
                           msg_out, msg_drop);

  return RETURN_SUC;
}

/* Routine for socket threads. Opens a socket and listens for incoming packets
 */
void *run_socket(void *args) {

  int sockfd, opt = 0;
  struct timeval timeout = {.tv_sec = 0, .tv_usec = RECV_TIMEOUT};
  struct sock_targ_t *targs = (struct sock_targ_t *)args;
  struct sockaddr_in6 server_addr;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(targs->thread_id, &cpuset);

  if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)) {
    error_msg("Failed to set cpu affinity of thread %d to cpu %d\n",
              pthread_self(), targs->thread_id);
  }

  if (block_signals(false)) {
    error_msg("Failed to block signals\n");
  }

  if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
    error_msg(
        "Could not open socket : %s\n",
        strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
    targs->return_code = RETURN_FAIL;
    return &targs->return_code;
  }

  // if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&opt,
  //                sizeof(opt)) == -1) {
  //   error_msg(
  //       "Cant set socket option SO_REUSEPORT : %s\n",
  //       strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
  //   close(sockfd);
  //   targs->return_code = RETURN_FAIL;
  //   return &targs->return_code;
  // }

  opt = 1;

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt)) ==
      -1) {
    error_msg(
        "Cant set socket option SO_REUSEPORT : %s\n",
        strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
    close(sockfd);
    targs->return_code = RETURN_FAIL;
    return &targs->return_code;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout,
                 sizeof(timeout)) == -1) {
    error_msg(
        "Cant set socket option SO_RCVTIMEO : %s\n",
        strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
    close(sockfd);
    targs->return_code = RETURN_FAIL;
    return &targs->return_code;
  }

  if (memset(&server_addr, 0, sizeof(server_addr)) == NULL) {
    error_msg("memset error in run_socket\n");
  }

  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_addr = in6addr_any;
  server_addr.sin6_port = htons(port);

  if (bind(sockfd, (struct sockaddr_in *)&server_addr, sizeof(server_addr)) ==
      -1) {
    error_msg(
        "Failed to bind socket to port %d : %s\n", port,
        strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
    close(sockfd);
    targs->return_code = RETURN_FAIL;
    return &targs->return_code;
  }

  if (listen_and_reply(sockfd, targs)) {
    error_msg("Listen and reply failed\n");
    close(sockfd);
    targs->return_code = RETURN_FAIL;
    return &targs->return_code;
  }

  close(sockfd);
  targs->return_code = RETURN_SUC;

  return &targs->return_code;
}

/* Cleanup dependent on ipc type */
int ipc_cleanup(struct sock_targ_t *sock_targs, uint8_t thread_count,
                enum ipc_type_t ipc_type) {

  int i, retval = IO_IPC_NULLPTR_ERR;

  switch (ipc_type) {
  case DISK:

    if (sock_targs[0].ipc_arg != NULL) {
      retval = close(((struct disk_arg_t *)sock_targs[0].ipc_arg)->logfile_fd);
    }

    for (i = 0; i < thread_count; i++) {
      if (sock_targs[i].ipc_arg != NULL) {
        io_uring_queue_exit(
            &((struct disk_arg_t *)sock_targs[i].ipc_arg)->ring);
        free(sock_targs[i].ipc_arg);
        sock_targs[i].ipc_arg = NULL;
      }
    }

    break;

  case SHM:

    if (sock_targs[0].ipc_arg != NULL) {
      retval = shmrbuf_finalize((union shmrbuf_arg_t *)sock_targs[0].ipc_arg,
                                SHMRBUF_WRITER);
      free(sock_targs[0].ipc_arg);

      for (i = 0; i < thread_count; i++) {
        sock_targs[i].ipc_arg = NULL;
      }
    }

    break;

  default:
    return IO_IPC_ARG_ERR;
  }

  return retval;
}

void memory_cleanup_main(pthread_t **threads, struct sock_targ_t **sock_targs) {

  free(*sock_targs);
  free(*threads);
  *sock_targs = NULL;
  *threads = NULL;
}

int main(int argc, char **argv) {

  int retval, logfile_fd;
  uint8_t i;
  pthread_t *threads;
  struct sock_targ_t *sock_targs;
  struct shmrbuf_writer_arg_t *shmrbuf_arg;
  fips_buf_arg_t fips_buf_arg;
  struct util_targ_t util_targ = {.interval = (size_t)UTIL_TIMEOUT};

  struct arguments args = {
      .ipc_set = false,
      .logfile = DEFAULT_LOG,
  };

  if (argp_parse(&argp, argc, argv, 0, 0, &args) == ARGP_ERR_UNKNOWN) {
    exit(EXIT_FAILURE);
  }

  if ((threads = calloc(sizeof(pthread_t), thread_count)) == NULL ||
      (sock_targs = calloc(sizeof(struct sock_targ_t), thread_count)) == NULL) {
    perror("Calloc failed");
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < thread_count; i++) {
    sock_targs[i].thread_id = i;
    sock_targs[i].log_count = 0;
    sock_targs[i].log_drop = 0;
    sock_targs[i].pkt_in = 0;
    sock_targs[i].pkt_out = 0;
  }

  switch (ipc_type) {
  case POSIX_IO:

    if ((sock_targs[0].ipc_arg = fopen(args.logfile, "a+")) == NULL) {
      perror("fopen failed");
      fprintf(stderr, "logfile: %s", args.logfile);
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }
    for (i = 1; i < thread_count; i++) {
        sock_targs[i].ipc_arg = sock_targs[0].ipc_arg;
      }

    info_msg("opened file %s\n", args.logfile);
    break;
        
  case DISK:

    if ((logfile_fd = open(args.logfile, OPEN_MODE, OPEN_PERM)) < 0) {
      perror("opening logfile failed");
      fprintf(stderr, "logfile: %s", args.logfile);
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }

    for (i = 0; i < thread_count; i++) {
      if ((sock_targs[i].ipc_arg = calloc(1, sizeof(struct disk_arg_t))) ==
          NULL) {
        perror("calloc failed");
      } else {
        ((struct disk_arg_t *)sock_targs[i].ipc_arg)->logfile_fd = logfile_fd;

        if (io_uring_queue_init(
                MAX_MSG, &((struct disk_arg_t *)sock_targs[i].ipc_arg)->ring,
                0)) {
          perror("io_uring queue init failed");
        } else {
          continue;
        }
      }

      ipc_cleanup(sock_targs, thread_count, ipc_type);
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }

    info_msg("opened file %s and initialized io_uring_queues\n", args.logfile);
    break;

  case SHM:

    if ((shmrbuf_arg = (struct shmrbuf_writer_arg_t *)calloc(
             sizeof(struct shmrbuf_writer_arg_t), 1)) == NULL) {
      perror("calloc failed");
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }

    shmrbuf_arg->line_count = (args.shm_lines) ? args.shm_lines : SHM_NLINES;
    shmrbuf_arg->line_size = (logshort) ? (STR_SIZE_IP6 + 1) : LOG_BUF_SIZE_IP6;
    shmrbuf_arg->shm_key = args.shm_key;
    shmrbuf_arg->segment_count = thread_count;
    shmrbuf_arg->reader_count =
        (args.shm_reader_count) ? args.shm_reader_count : NREADERS;
    shmrbuf_arg->flags = (args.overwrite)
                             ? SHMRBUF_OVWR | SHMRBUF_REATT | SHMRBUF_FRCAT
                             : SHMRBUF_REATT | SHMRBUF_FRCAT;

    if ((retval = shmrbuf_init((union shmrbuf_arg_t *)shmrbuf_arg,
                               SHMRBUF_WRITER)) != IO_IPC_SUCCESS) {
      if (retval > 0) {
        perror("shm_rbuf_init failed");
      } else {
        fprintf(stderr, "shm_rbuf_init failed : error code %d\n", retval);
      }
      free(shmrbuf_arg);
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }

    for (i = 0; i < thread_count; i++) {
      sock_targs[i].ipc_arg = shmrbuf_arg;
    }

    break;

  case FIPS:

    fips_buf_arg.role = FIPS_WRITER;
    char *config_file = getenv("FIPS_BUF_CONF");
    if (config_file)
      retval = fips_buf_init(&fips_buf_arg, config_file);
    else
      retval = fips_buf_init(&fips_buf_arg, "/etc/fips_buf.conf");

    if (retval != FIPS_BUF_SUCCESS) {
      fprintf(stderr, "shm_rbuf_init failed : error code %d\n", retval);
      memory_cleanup_main(&threads, &sock_targs);
      exit(EXIT_FAILURE);
    }

    for (i = 0; i < thread_count; i++) {
      sock_targs[i].ipc_arg = &fips_buf_arg;
    }

    break;

  default:
    fprintf(stderr, "Invalid ipc type value %d\n", ipc_type);
    memory_cleanup_main(&threads, &sock_targs);
    exit(EXIT_FAILURE);
  }

  if (update_datetime(global_datetime_buf) == RETURN_FAIL) {
    fprintf(stderr, "Initializing the global datetime buffer failed\n");
    ipc_cleanup(sock_targs, thread_count, ipc_type);
    memory_cleanup_main(&threads, &sock_targs);
    exit(EXIT_FAILURE);
  }

  if (pthread_create(&threads[0], NULL, util_thread_routine,
                     (void *)&util_targ)) {
    perror("Creating util thread failed");
    ipc_cleanup(sock_targs, thread_count, ipc_type);
    memory_cleanup_main(&threads, &sock_targs);
    exit(EXIT_FAILURE);
  }

  for (i = 1; i < thread_count; i++) {

    if (pthread_create(&threads[i], NULL, run_socket, (void *)&sock_targs[i])) {
      perror("Could not create listener thread");
    }
  }

  run_socket((void *)&sock_targs[0]);

  for (i = 0; i < thread_count; i++) {
    if (pthread_join(threads[i], NULL)) {
      perror("Pthread join failed");
    }
  }

  unsigned long long int total_in_count = 0, total_out_count = 0,
                         total_log_count = 0, total_drop_count = 0;

  printf("\n");

  for (i = 0; i < thread_count; i++) {
    if (sock_targs[i].return_code != RETURN_SUC) {
      fprintf(stderr, "Thread %d terminated with an error : error code %d\n", i,
              sock_targs[i].return_code);
    }

    printf("Thread %d : packets received: %lu, packets sent: %lu, messages "
           "logged: %lu, messages dropped: %lu\n",
           i, sock_targs[i].pkt_in, sock_targs[i].pkt_out,
           sock_targs[i].log_count, sock_targs[i].log_drop);

    total_in_count += sock_targs[i].pkt_in;
    total_out_count += sock_targs[i].pkt_out;
    total_log_count += sock_targs[i].log_count;
    total_drop_count += sock_targs[i].log_drop;
  }

  printf("Total packets received: %llu, total packets sent: %llu, total "
         "messages logged: %llu, total messages dropped: %llu\n",
         total_in_count, total_out_count, total_log_count, total_drop_count);

  if (util_targ.return_code == RETURN_FAIL) {
    fprintf(stderr, "Util thread returned an error\n");
  }

  retval = ipc_cleanup(sock_targs, thread_count, ipc_type);

  if (retval != IO_IPC_SUCCESS) {
    fprintf(stderr, "Error in ipc cleanup : error code %d\n", retval);
  }

  memory_cleanup_main(&threads, &sock_targs);

  return EXIT_SUCCESS;
}
