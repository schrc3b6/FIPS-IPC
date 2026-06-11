#include "simplefail2ban.h"
#include <stdio.h>

int ban_clients(struct hs_context_t *context, struct iovec *iovecs,
                int parsed_lines, uint64_t *ban_count, uint64_t *too_old, __u64 *values
#ifdef GRPC
                ,
                intervention_client_t gRPC_Client
#endif
) {
  int retval = 0;
#ifdef GRPC
  int request_length = 0;
  intervention_client_request_t request = getBlockRequest(gRPC_Client);
#endif
  for (int i = 0; i < parsed_lines; i++) {
    time_t ts = time(NULL);

    // disregard too old log messages
    // fprintf(stderr, "message ts: %ld, ts: %ld \n", context->timestamp, ts);
    if (ts - context->timestamp > server.config.findtime) {
      // fprintf(stderr, "can't keep up");
      (*too_old)++;
      continue;
    }

    // Query htable for the number of times an ip address has been logged
    switch (context[i].domain) {
    case AF_INET:
      if (is_whitelistv4(context[i].ip_addr.ipv4,
                         server.config.whitelistv4.s_addr, 24)) {
        continue;
      }
      retval = ip_hashtable_insert(server.htable, &context[i].ip_addr.ipv4,
                                   AF_INET, context[i].timestamp);
      break;

    case AF_INET6:

      retval = ip_hashtable_insert(server.htable, &context[i].ip_addr.ipv6,
                                   AF_INET6, context[i].timestamp);
      break;

    default:
      continue;
    }

    if (retval < 1) {
      error_msg("Error in htable query for logstring : %s : Error Code %d\n",
                iovecs[i].iov_base, retval);
      continue;
    }

    // Ban client if ban threshold has been reached
    if (retval == server.config.limit) {

      switch (context[i].domain) {
      case AF_INET:

        if ((retval = ip_llist_push(server.banned_list,
                                    &context[i].ip_addr.ipv4, &ts, AF_INET)) <
            0) {
          error_msg("Error pushing to banned list for logstring : %s : "
                    "Error Code %d\n",
                    iovecs[i].iov_base, retval);
          continue;
        }

#ifdef GRPC
        add_ipv4_to_request(gRPC_Client, request, context[i].ip_addr.ipv4);
        request_length++;
#else
        retval =
            bpf_map_update_elem(server.ipv4_ebpf_map, &context[i].ip_addr.ipv4,
                                &values, BPF_NOEXIST);
#endif

        break;

      case AF_INET6:

        if ((retval = ip_llist_push(server.banned_list,
                                    &context[i].ip_addr.ipv6, &ts, AF_INET6)) <
            0) {
          error_msg("Error pushing to banned list for logstring : %s : "
                    "Error Code %d\n",
                    iovecs[i].iov_base, retval);
          continue;
        }
#ifdef GRPC
        add_ipv6_to_request(gRPC_Client, request,
                            (uint8_t *)&context[i].ip_addr.ipv6);
        request_length++;
#else
        retval =
            bpf_map_update_elem(server.ipv6_ebpf_map, &context[i].ip_addr.ipv6,
                                &values, BPF_NOEXIST);
#endif

        break;

      default:
        continue;
      }

      if (retval != EXIT_OK) {
        error_msg("Error adding entry to ebpf map : Error code %d : "
                  "logstring : %s\n",
                  retval, iovecs[i].iov_base);

        if ((retval = ip_hashtable_set(
                 server.htable, &context[i].ip_addr, context[i].domain,
                 server.config.limit - 1, context[i].timestamp)) < 0) {
          error_msg("ip_hashtable set failed, Error code: %d, logstring: %s\n",
                    retval);
        }

        continue;
      }

      (*ban_count)++;
    }
  }
#ifdef GRPC
  if (request_length){
    sendBlockRequest(gRPC_Client, request);
  }else{
    deleteBlockRequest(request);
  }
#endif

  return 0;
}

int parse_str(char *logstr, struct hs_context_t *context,
              hs_scratch_t *scratch) {

  int retval;

  // If matching enabled, matches log message against regex
  context->match = false;
  context->domain = -1;
  context->logstr = logstr;
  context->rate_limit_match = false;

  static __thread char timestamp_str_cache[21];
  static __thread time_t timestamp_cache = 0;
  // parse the time stamp at the start of the string
  if (memcmp(logstr, timestamp_str_cache, 21)) {
    memcpy(timestamp_str_cache, logstr, 21);
    struct tm tm = {0};
    void *ret = strptime(logstr, DATE_FMT, &tm);
    if (ret == NULL) {
      timestamp_cache = time(NULL);
    } else {
      tm.tm_isdst=1;
      timestamp_cache = mktime(&tm);
    }
  }
  context->timestamp = timestamp_cache;

  if ((retval = hs_scan(server.database, logstr, LINEBUF_SIZE, 0, scratch,
                        regex_match_handler, context)) != HS_SUCCESS &&
      retval != HS_SCAN_TERMINATED) {
    error_msg("Hyperscan error for logstring %s : error code %d\n", logstr,
              retval);
    return -1;
  }
  // check if regex match or domain was not found
  // if this is the case, then continue with next logstring
  if (!context->match || context->domain == -1 ||
      context->rate_limit_match == false) {
    // fprintf(stderr, "match %d, domain %d, rate_limit_match %d\n", context->match, context->domain, context->rate_limit_match);
    return -2;
  }

  // Try to convert log message to IP address
  // BUG: this, this should be determined by context!!!
  // printf("trying to convert ip str: %s ",logstr); 
  if (inet_pton(AF_INET, &context->logstr[context->from], &context->ip_addr.ipv4) == 1) {
    context->domain = AF_INET;
  } else if (inet_pton(AF_INET6, &context->logstr[context->from], &context->ip_addr.ipv6) == 1) {
    context->domain = AF_INET6;
  } else {
    return -3;
  }
  return 0;
}

// Todo: Unittest for regex match
int regex_match_handler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
  /**
   *  Description : Handler function that is called if hs_scan finds a match.
   *
   *  Parameters :
   * 		unsigned int id : ID of the matched regular expression (see
   * hs_compile) unsigned long long from : Start index of the match unsigned
   * long long to : End index of the match unsigned int flags : Flags set for
   * match void *ctx : Context pointer, expects pointer to struct ban_targs_t
   *
   *  Returns :
   * 		int : 0, if matching should continue, 1 else.
   */

  UNUSED(flags);

  struct hs_context_t *context = (struct hs_context_t *)ctx;
  int return_value;

  switch (id) {
  // checks if logstring contains rate limit substring
  // hyperscan search terminates only if IP address is also found
  case RATE_LIMIT_REGEX_ID:
    context->rate_limit_match = true;
    // printf("matchted: %s \n", RATE_LIMIT_REGEX);
    return (context->match) ? 1 : 0;

  // checks if logstring contains ipv4 address
  // hyperscan search terminates only if rate limit substring is also found
  case IP4_REGEX_ID:
    context->match = true;
    context->logstr[to - 1] = '\0';
    context->from = from;
    // printf("matched ipv4: %s\n", &context->logstr[from]);

// #ifndef GRPC
    if (inet_pton(AF_INET, &context->logstr[from], &context->ip_addr.ipv4) ==
        1) {
      context->domain = AF_INET;
      return_value = ((context->match) && (context->rate_limit_match)) ? 1 : 0;
      return return_value;
    }
// #endif
//
// #ifdef GRPC
//     context->domain = AF_INET;
//     return_value = ((context->match) && (context->rate_limit_match)) ? 1 : 0;
//     return return_value;
// #endif
//
    context->domain = -1;
    context->logstr[to] = ' ';

    return 0;

  // checks if logstring contains ipv6 address
  // hyperscan search terminates only if rate limit substring is also found
  case IP6_REGEX_ID:

    context->match = true;
    context->logstr[to - 1] = '\0';
    context->from = from;

// #ifndef GRPC
    if (inet_pton(AF_INET6, &context->logstr[from], &context->ip_addr.ipv6) ==
        1) {
      context->domain = AF_INET6;
      context->logstr[to + 1] = ' ';
      return_value = ((context->match) && (context->rate_limit_match)) ? 1 : 0;
      return return_value;
    }
// #endif
//
// #ifdef GRPC
//     context->domain = AF_INET6;
//     context->logstr[to + 1] = ' ';
//     return_value = ((context->match) && (context->rate_limit_match)) ? 1 : 0;
//     return return_value;
// #endif
//
    context->domain = -1;
    context->logstr[to + 1] = ' ';
    return 0;

  default:
    return 1;
  }
}

void *ban_thread_routine(void *args) {
  /**
   *	Description: This this function represents the routine executed
   *   by the banning threads. While the global parameter "server_running"
   *   is true, the choosen ipc api is queried for incoming messages. Messages
   *   are then parsed, and identified clients are logged to htable. If the
   *banning threshold has been exeeded, the clients ip is added to banned_list
   *and the corresponding ebpf map.
   *
   *   Parameters:
   *   	void * args : Pointer to struct ban_targs_t with thread parameters
   *
   *   Returns:
   * 		void * : Pointer to int returncode of the function
   **/

  struct ban_targs_t *targs = (struct ban_targs_t *)args;
  hs_scratch_t *scratch = NULL;
  // struct hs_context_t context;
  struct timespec tspec = {.tv_sec = 0, .tv_nsec = targs->wakeup_interval};
  struct iovec iovecs[QUEUE_SIZE];
  struct hs_context_t context[QUEUE_SIZE];
  char *logstr_buf;
  uint64_t rcv_count = 0, ban_count = 0, steal_count = 0, too_old = 0;
  int recv_retval = 0, i;

  // create gRPC connection
// connection only if gRPC is set
#ifdef GRPC
  intervention_client_t gRPC_Client;
  gRPC_Client = intervention_client_create();
#endif

  // create regex to find IP addresses as substring in log message

  int nr_cpus = libbpf_num_possible_cpus();
  __u64 values[nr_cpus];
  memset(&values, 0, sizeof(values));

  if ((logstr_buf = (char *)calloc(QUEUE_SIZE, LINEBUF_SIZE)) == NULL) {
    error_msg("calloc failed : %s\n", strerror_r(errno, targs->strerror_buf,
                                                 sizeof(targs->strerror_buf)));
    targs->retval = EXIT_FAIL;
    return &targs->retval;
  }

  for (i = 0; i < QUEUE_SIZE; i++) {
    iovecs[i].iov_base = &logstr_buf[LINEBUF_SIZE * i];
    iovecs[i].iov_len = LINEBUF_SIZE;
  }

  ipc_args_t *ipc_arg;

  int result = init_thread_ipc(targs, &ipc_arg);
  if (result == -1) {
    return &targs->retval;
  }

  if (block_signals(false)) {
    error_msg("failed to block signals\n");
  }

  if (hs_alloc_scratch(server.database, &scratch) != HS_SUCCESS) {
    error_msg("hyperscan scratch space allocation failed\n");
    free(logstr_buf);
    targs->retval = EXIT_FAIL;
    return &targs->retval;
  }

  // Event loop
  while (server.server_running) {

    // Message receiving dependent on ipc_type
    recv_retval = get_lines_ipc(targs, ipc_arg, iovecs);
    if (recv_retval < 0) {
      error_msg("uring_getlines failed with error code %d\n", recv_retval);
      free(logstr_buf);
      targs->rcv_count = rcv_count;
      targs->ban_count = ban_count;
      targs->too_old = too_old;
      targs->steal_count = steal_count;
      targs->retval = EXIT_FAIL;
      return &targs->retval;
    }
    // fprintf(stderr, "iovec: %s\n",iovecs[0].iov_base);

    if (recv_retval == 0) {
      nanosleep(&tspec, NULL);
      continue;
    }

    rcv_count += recv_retval;

    int parsed_lines = 0;
    for (i = 0; i < recv_retval; i++) {
      // printf("%s\n",(char *)iovecs[i].iov_base);
      int ret = parse_str((char *)iovecs[i].iov_base, &context[parsed_lines],
                          scratch);
      if (ret < 0) {
        // printf("parse_str returned %d \n", ret);
        continue;
      }
      parsed_lines++;
    }
    // printf("parsed_lines: %d \n", parsed_lines);

#ifdef GRPC
    ban_clients(context, iovecs, parsed_lines, &ban_count, &too_old, values, gRPC_Client);
#else
    ban_clients(context, iovecs, parsed_lines, &ban_count, &too_old, values);
#endif

    return_lines_ipc(targs, ipc_arg, iovecs);
    // Timeout, if no messages were read
  }

#ifdef GRPC
  // destroy gRPC Client
  intervention_client_destroy(gRPC_Client);
#endif
  deinit_thread_ipc(targs, ipc_arg);

  hs_free_scratch(scratch);
  free(logstr_buf);
  targs->rcv_count = rcv_count;
  targs->ban_count = ban_count;
  targs->too_old = too_old;
  targs->steal_count = steal_count;
  targs->retval = EXIT_SUCCESS;
  return &targs->retval;
}
