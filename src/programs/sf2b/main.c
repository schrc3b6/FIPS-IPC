#include "simplefail2ban.h"

// Default configuration
// global variables

// intialize server with defaults
server_t server = {
    .config =
        {
            .ipc_type = DEFAULT_IPC_TYPE,
            .thread_count = NTHREADS,
            .bantime = DEFAULT_BAN_TIME,
            .limit = DEFAULT_BAN_THRESHOLD,
            .findtime = DEFAULT_BAN_FINDTIME,
            .matching = false,
            .verbose = false,
            .wload_stealing = false,
            .shm_key = DEFAULT_LOG,
            .logfile = DEFAULT_LOG,
            .regex = IP4_REGEX,
            .regex_rate_limit = RATE_LIMIT_REGEX,
            .interface = DEFAULT_IFACE,
            // no defualts:
            //   whitelistv4;
            //   whitelistv6;
        },
    .server_running = true,
    .stdout_lock = PTHREAD_MUTEX_INITIALIZER,
    .stderr_lock = PTHREAD_MUTEX_INITIALIZER,

    // setting in init
    // struct ip_hashtable_t * htable;
    // struct ip_llist_t * banned_list;
    // hs_database_t * database;
    // int ipv4_ebpf_map;
    // int ipv6_ebpf_map;
};

// Argparse
const char *argp_program_version = "Simplefail2ban 2.0";
static const char argp_program_doc[] =
    "Simplefail2ban with gRPC support.\n"
    "\n"
    "A minimal eBPF based IPS for testing purposes";

static char args_doc[] = "INTERFACE";

static const struct argp_option opts[] = {

    {"file", 'f', "FILE", OPTION_ARG_OPTIONAL,
     "Set logifle as the chosen ipc type (optional: specify path to logfile)",
     0},
    {"shm", 's', "KEY", OPTION_ARG_OPTIONAL,
     "Set shared memory as the ipc type (optional: specify file for shared "
     "memory key)",
     0},
    {"posix", 'p', "FILE", OPTION_ARG_OPTIONAL,
     "Set posix io logifle as the chosen ipc type (optional: specify path to "
     "logfile)",
     0},
    {"threads", 't', "N", OPTION_ARG_OPTIONAL,
     "Enable multi-threading (optional: set number of banning threads to use)",
     0},
    {"limit", 'l', "N", 0, "Set number of matches before a client is banned",
     0},
    {"bantime", 'b', "N", 0, "Set number of seconds a client should be banned",
     0},
    {"findtime", 'd', "N", 0,
     "Set number of seconds in which the limit has to be reached", 0},
    {"match", 'm', "REGEX", OPTION_ARG_OPTIONAL,
     "Use regex matching on logstrings (optional: specify match regex to use)",
     0},
    {"steal", 'w', NULL, 0, "Enable workload stealing for shared memory", 0},
    {"verbose", 'v', NULL, 0, "Enable debug output", 0},
    {"grpc", 'g', "IP", OPTION_ARG_OPTIONAL,
     "Set the target IP address for gRPC calls", 0},
    {0},
};

// Arguments parser for argparse
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  // char *grpc_ip = NULL;
  switch (key) {

  case 'f':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one IPC type can be specified\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    server.config.ipc_type = DISK;

    if (arg != NULL) {
      server.config.logfile = arg;
    }

    break;

  case 'p':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one IPC type can be specified\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    server.config.ipc_type = POSIX_IO;

    if (arg != NULL) {
      server.config.logfile = arg;
    }

    break;

  case 's':

    if (arguments->ipc_set) {
      fprintf(stderr, "Only one IPC type can be specified\n");
      argp_usage(state);
    }

    arguments->ipc_set = true;
    server.config.ipc_type = SHM;

    if (arg) {
      server.config.shm_key = arg;
    }

    else {
      server.config.shm_key = DEFAULT_LOG;
    }

    break;

  case 't':
    if (arg) {
      server.config.thread_count = (uint8_t)strtol(arg, NULL, 10);

      if (get_nprocs() < server.config.thread_count) {
        server.config.thread_count = get_nprocs();
        fprintf(stderr, "Using maximum number of banning threads = %d\n",
                server.config.thread_count);
      }

      if (server.config.thread_count == 0) {
        server.config.thread_count = 1;
        fprintf(stderr, "Minimum 1 banning thread required\n");
      }
    }

    else {
      server.config.thread_count = DEFAULT_THREAD_COUNT;
    }

    break;

  case 'l':

    server.config.limit = (uint16_t)strtol(arg, NULL, 10);

    if (server.config.limit == 0) {
      fprintf(stderr, "Ban limit has to be at least 1\n");
      server.config.limit = DEFAULT_BAN_THRESHOLD;
    }

    break;

  case 'b':

    server.config.bantime = (uint16_t)strtol(arg, NULL, 10);
    if (server.config.bantime == 0) {
      fprintf(stderr, "Ban time has to be at least 1\n");
      server.config.bantime = DEFAULT_BAN_TIME;
    }

    break;

  case 'd':

    server.config.findtime = (uint16_t)strtol(arg, NULL, 10);
    if (server.config.findtime == 0) {
      fprintf(stderr, "Find time has to be at least 1\n");
      server.config.findtime = DEFAULT_BAN_FINDTIME;
    }

    break;

  case 'r': // TODO: not used?

    server.config.matching = true;

    if (arg != NULL) {
      server.config.regex = arg;
    }

    break;

  case 'm':

    server.config.matching = true;
    break;

  case 'w':

    server.config.wload_stealing = true;
    break;

  case 'v':

    server.config.verbose = true;
    break;

  case 'g':

    if (arg) {
      struct sockaddr_in sa;
      int ip_result = inet_pton(AF_INET, arg, &(sa.sin_addr));
      if (ip_result == 0) {
        fprintf(stderr, "No valid IP address for grpc backend given. Using "
                        "default IP address 10.3.10.43\n");
      } else {
        arguments->grpc_ip = arg;
      }
    }

    break;

  case ARGP_KEY_ARG:
    if (state->arg_num >= 2) {
      fprintf(stderr, "Too many arguments. See usage\n");
      argp_usage(state);
    }

    server.config.interface = arg;

    break;
  case ARGP_KEY_END:
    if (state->arg_num < 1) {
      server.config.interface = DEFAULT_IFACE;
    }

    if (server.config.thread_count > 1 &&
        (server.config.ipc_type == DISK ||
         server.config.ipc_type == POSIX_IO)) {
      fprintf(stderr, "No multithreading available for FILE IPC\n");
      server.config.thread_count = 1;
    }

    if (server.config.wload_stealing && server.config.ipc_type != SHM) {
      server.config.wload_stealing = false;
    }

    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .args_doc = args_doc,
    .doc = argp_program_doc,
};
uint32_t cidr_to_mask(int cidr) {
    return htonl((uint32_t)(0xFFFFFFFF << (32 - cidr)));
}


bool is_whitelistv4(uint32_t address, uint32_t subnet, uint8_t subnet_size) {
    uint32_t mask = cidr_to_mask(subnet_size);
    // Apply the subnet mask to both the IP address and the subnet address
    return (address & mask) == (subnet & mask);
  // return (address << (32 - subnet_size)) & (subnet << (32 - subnet_size));
}

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char *fmt, pthread_mutex_t *lock, FILE *fp,
                  va_list targs) {
  pthread_mutex_lock(lock);
  vfprintf(fp, fmt, targs);
  pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char *fmt, ...) {
  va_list targs;
  va_start(targs, fmt);
  sync_message(fmt, &server.stdout_lock, stdout, targs);
  va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char *fmt, ...) {
  va_list targs;
  va_start(targs, fmt);
  sync_message(fmt, &server.stderr_lock, stderr, targs);
  va_end(targs);
}

void sig_handler(int signal) {
  // UNUSED(signal);
  if (signal == SIGINT) {
    server.server_running = false;
  }
}

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

  return RETURN_SUCC;
}


// get unban list
// currently new entries are added to the front of the list
// therefore we need to iterate through the list to find the first entry
// that has a timestamp older than the bantime
struct ip_listnode_t *get_unban_list() {
  struct ip_listnode_t *iterator = NULL, *prev = NULL;
  char strerror_buf[64];
  time_t ts;

  ts = time(NULL);
  if (pthread_mutex_lock(&server.banned_list->lock)) {
    pthread_mutex_unlock(&server.banned_list->lock);
    error_msg("Failed to claim banned list lock : %s\n",
              strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
    return (void *)-1;
  }

  // Find first entry in the banned_list whos bantime has elapsed.
  iterator = server.banned_list->head;

  // ceck if list is empty
  if (iterator == NULL) {
    if (pthread_mutex_unlock(&server.banned_list->lock)) {
      error_msg("Failed to claim banned list lock : %s\n",
                strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
      return (void *)-1;
    }
    return NULL;
  }

  // if the first entry needs unbanning empty the list
  if ((ts - iterator->timestamp) > server.config.bantime) {
    server.banned_list->head = NULL;
    if (pthread_mutex_unlock(&server.banned_list->lock)) {
      error_msg("Failed to claim banned list lock : %s\n",
                strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
      return (void *)-1;
    }
    return iterator;
  }

  prev = iterator;
  iterator = iterator->next;

  // we can unlock here since new entries are added to the front of the list
  if (pthread_mutex_unlock(&server.banned_list->lock)) {
    error_msg("Failed to claim banned list lock : %s\n",
              strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
    return (void *)-1;
  }

  while (iterator != NULL) {

    if ((ts - iterator->timestamp) > server.config.bantime) {
      prev->next = NULL;
      return iterator;
    }
    prev = iterator;
    iterator = iterator->next;
  }
  return NULL;
}

void *unban_thread_routine(void *args) {
  /**
   *	Description: This this function represents the routine executed
   *   by the unbanning thread. While the global parameter "server_running"
   *   is true, it periodically wakes up and iterates through the banned_list,
   *   to unban clients whos bantime has elapsed.
   *
   *   Parameters:
   *   	void * args : Pointer to struct unban_targs_t with thread parameters
   *
   *   Returns:
   * 		void * : Pointer to int returncode of the function
   **/

  struct unban_targs_t *targs = (struct unban_targs_t *)args;
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = targs->wakeup_interval};
  char strerror_buf[64];
  struct ip_listnode_t *iterator, *prev;
  int retval;
  bool idle;

#ifdef GRPC
  intervention_client_t client = intervention_client_create();
#endif

  // Blocks (blockable) signals except SIGINT and SIGTERM
  if (block_signals(true)) {
    error_msg("Failed to block signals\n");
  }

  // Registers sig_handler to handle SIGINT and SIGTERM (-> server_running =
  // false)
  if (signal(SIGINT, sig_handler) == SIG_ERR ||
      signal(SIGTERM, sig_handler) == SIG_ERR) {
    error_msg("Failed to set signal handler : %s\n",
              strerror_r(errno, strerror_buf, sizeof(strerror_buf)));
  }

  // Event loop
  while (server.server_running) {

    idle = true;

    iterator = get_unban_list();
    if (iterator == (void *)-1) {
      targs->retval = EXIT_FAIL;
      return &targs->retval;
    }

    if (iterator != NULL) {
      idle = false;
    }


#ifdef GRPC
    intervention_client_request_t request = getUnblockRequest(client);
#endif
    // Unban all clients with an elapsed bantime
    while (iterator != NULL) {
        retval = 0;
      switch (iterator->domain) {
      case AF_INET:
#ifdef GRPC
        add_ipv4_to_request(client, request, *(uint32_t*)iterator->key);
#else
        retval = bpf_map_delete_elem(server.ipv4_ebpf_map, iterator->key);
#endif
        ip_hashtable_set(server.htable, iterator->key, AF_INET, 0, time(NULL));
        break;

      case AF_INET6:
#ifdef GRPC
        add_ipv6_to_request(client, request, iterator->key);
#else
        retval = bpf_map_delete_elem(server.ipv6_ebpf_map, iterator->key);
#endif
        ip_hashtable_set(server.htable, iterator->key, AF_INET6, 0, time(NULL));
        break;

      default:
        retval = -1;
        error_msg("Invalid domain in banned list %d\n", iterator->domain);
      }

      if (retval != 0) {
        error_msg("Error deleting entry from ebpf map : error code %d\n",
                  retval);
      } else {
        targs->unban_count++;
      }

      prev = iterator;
      iterator = iterator->next;

      // freeing the memory
      if ((retval = ip_llist_remove(&prev, NULL)) < 0) {
        error_msg("Error removing node from banned list : error code %d\n",
                  retval);
      }
    }

#ifdef GRPC
    sendUnblockRequest(client,  request);
#endif

    // Timeout after checking banned_list
    if (idle) {
      nanosleep(&timeout, NULL);
    }
  }

#ifdef GRPC
  intervention_client_destroy(client);
#endif
  targs->retval = EXIT_SUCCESS;
  return &targs->retval;
}


bool main_cleanup(struct ban_targs_t **targs, pthread_t **tids) {
  /**
   * Description : Cleans up memory and io channels for the main function
   *
   * Parameters :
   * 		 struct ban_targs_t ** targs : Pointer to array of thread
   * argument structs pthread_t ** tids : Pointer to arry of thread ids
   *
   * Returns :
   * 		bool : true, if an error occured, else false
   */

  int retval;
  bool error = false;

  if (targs != NULL && *targs != NULL && (*targs)[0].ipc_args != NULL) {

    error = cleanup_ipc(targs);
    free(*targs);
    free(*tids);
    *targs = NULL;
    *tids = NULL;
  }

  if ((retval = ebpf_cleanup(server.config.interface, true,
                             server.config.verbose)) < 0) {
    fprintf(stderr, "ebpf cleanup failed : error code %d\n", retval);
    error = true;
  }

  if (server.banned_list != NULL) {
    if ((retval = ip_llist_destroy(&server.banned_list)) != IP_LLIST_SUCCESS) {
      fprintf(stderr, "ip_llist_destroy failed with error code %d\n", retval);
      error = true;
    }
  }

  if (server.htable != NULL) {
    if ((retval = ip_hashtable_destroy(&server.htable)) < 0) {
      fprintf(stderr, "ip_hashtable_destroy failed with error code %d\n",
              retval);
      error = true;
    }
  }

  if (server.database != NULL) {
    if ((retval = hs_free_database(server.database)) != HS_SUCCESS) {
      fprintf(stderr, "hs_free_database failed with error code %d\n", retval);
      error = true;
    }
  }

  return error;
}

int main(int argc, char **argv) {
  /**
   * Description : Main function of the program. Parses commandline arguments,
   * sets up the ipc api, loads the ebpf program, spawns unbanning and banning
   * threads.
   *
   *
   */
  // Variables
  struct arguments args = {.ipc_set = false, .grpc_ip = "10.3.10.43"};
  struct ban_targs_t *thread_args = NULL;
  struct unban_targs_t unban_targs = {.unban_count = 0,
                                      .wakeup_interval = TIMEOUT};
  pthread_t *thread_ids = NULL;
  int retval;
  uint8_t i;

  // TODO: make this whitelist configurable and actually allow multible entries
  inet_pton(AF_INET, "10.3.30.0", &server.config.whitelistv4);

  // Parse commandline arguments
  retval = argp_parse(&argp, argc, argv, 0, NULL, &args);


  if (retval == ARGP_ERR_UNKNOWN) {
    exit(EXIT_FAILURE);
  }

  // FIXME: This is a hack to get the IP address of the gRPC backend into the
  // environment variable
  //  create and add environment variable with gRPC backend IP Address
  //  #ifdef GRPC
  //  	char environment_variable[30] = "LB_IP_ADDRESS=";
  //  	strcat(environment_variable, args.grpc_ip);
  //  	int ret = putenv(environment_variable);
  //  	if(ret){
  //  		fprintf(stderr, "Error on adding environment variable: %d\n",
  //  ret);
  //  	}
  //  	else{
  //  		fprintf(stdout, "Added IP address %s as environment variable\n",
  //  args.grpc_ip);
  //  	};
  //  #endif

  // Setup regex matching, compile chosen regex.
  init_hs();

// Load ebpf program onto chosen interface and setup maps
#ifdef DEBUG
  printf("%s \n", interface);
#endif
#ifndef GRPC
  if (ebpf_setup(server.config.interface, server.config.verbose)) {
    fprintf(stderr, "ebpf setup failed\n");
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  if ((server.ipv4_ebpf_map = open_bpf_map(FILE_BLACKLIST_IPV4)) ==
          RETURN_FAIL ||
      (server.ipv6_ebpf_map = open_bpf_map(FILE_BLACKLIST_IPV6)) ==
          RETURN_FAIL) {
    fprintf(stderr, "failed to open bpf map  : %s\n", strerror(errno));
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }
  server.config.bpf_nr_cpus = libbpf_num_possible_cpus();
#endif

  // Init memory for thread arguments
  if ((thread_ids = (pthread_t *)calloc(sizeof(pthread_t),
                                        server.config.thread_count)) == NULL ||
      (thread_args = (struct ban_targs_t *)calloc(
           sizeof(struct ban_targs_t), server.config.thread_count)) == NULL) {
    perror("calloc failed");
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  // Init hashtable for tracking of logged ip addresses
  if ((retval = ip_hashtable_init(&server.htable, server.config.findtime)) <
      0) {
    fprintf(stderr, "ip_hashtable_init failed with error code %d\n", retval);
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  // Init linked list for tracking of banned ip addresses
  if ((retval = ip_llist_init(&server.banned_list)) < 0) {
    fprintf(stderr, "ip_llist_init failed with error code %d\n", retval);
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  if (init_ipc(thread_args) < 0) {
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  // Create unbanning thread
  if (pthread_create(&thread_ids[0], NULL, unban_thread_routine,
                     &unban_targs)) {
    perror("pthread create failed for unban thread");
    main_cleanup(&thread_args, &thread_ids);
    exit(EXIT_FAILURE);
  }

  else {
    // Create banning threads
    for (i = 0; i < server.config.thread_count; i++) {
      thread_args[i].ban_count = 0;
      thread_args[i].too_old = 0;
      thread_args[i].rcv_count = 0;
      thread_args[i].thread_id = i;
      thread_args[i].wakeup_interval = TIMEOUT;

      if (i > 0) {
        if (pthread_create(&thread_ids[i], NULL, ban_thread_routine,
                           &thread_args[i])) {
          perror("pthread create failed");
        }
      }
    }

    // Start main event loop
    ban_thread_routine(&thread_args[0]);

    for (i = 0; i < server.config.thread_count; i++) {
      if (pthread_join(thread_ids[i], NULL)) {
        perror("pthread join failed");
      }
    }
  }

  uint64_t total_rcv_count = 0, total_ban_count = 0, total_steal_count = 0;

  printf("\n");

  // Aggregate and print receive and ban / unban counters.
  for (i = 0; i < server.config.thread_count; i++) {
    if (thread_args[i].retval != RETURN_SUCC) {
      fprintf(stderr, "Banning thread %d returned with error code %d\n", i,
              thread_args[i].retval);
    }

    if (server.config.wload_stealing) {
      printf("Thread %d : messages received: %ld, messages stolen: %ld, "
             "clients banned: %ld, too old messages %ld\n",
             i, thread_args[i].rcv_count, thread_args[i].steal_count,
             thread_args[i].ban_count, thread_args[i].too_old);
    } else {
      printf("Thread %d : messages received: %ld, clients banned: %ld, too old messages %ld\n", i,
             thread_args[i].rcv_count, thread_args[i].ban_count, thread_args[i].too_old);
    }

    total_rcv_count += thread_args[i].rcv_count;
    total_ban_count += thread_args[i].ban_count;
    total_steal_count += thread_args[i].steal_count;
  }

  if (unban_targs.retval != RETURN_SUCC) {
    fprintf(stderr, "Unban thread returned with error code %d\n",
            thread_args[i].retval);
  }

  if (server.config.wload_stealing) {
    printf("Total messages received: %ld, total messages stolen: %ld, total "
           "clients banned: %ld, total clients unbanned: %ld\n",
           total_rcv_count, total_steal_count, total_ban_count,
           unban_targs.unban_count);

  } else {
    printf("Total messages received: %ld, total clients banned: %ld, total "
           "clients unbanned: %ld\n",
           total_rcv_count, total_ban_count, unban_targs.unban_count);
  }

  if (main_cleanup(&thread_args, &thread_ids)) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
