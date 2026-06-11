#include "simplefail2ban.h"
#include <stdio.h>

int init_hs() { return 0; }

int ban_clients(struct iovec *iovecs, int parsed_lines, uint64_t *ban_count, uint64_t *too_old,
                __u64 *values
#ifdef GRPC
                ,
                intervention_client_t gRPC_Client
#endif
) {
  int retval = 0;
  fips_bin_message_t *message;
#ifdef GRPC
  int request_length = 0;
  intervention_client_request_t request = getBlockRequest(gRPC_Client);
#endif
  for (int i = 0; i < parsed_lines; i++) {
    message = (fips_bin_message_t *)iovecs[i].iov_base;
    time_t ts = time(NULL);

    // disregard too old log messages
    if (ts - message->timestamp > server.config.findtime) {
      too_old++;
      continue;
    }

    // Query htable for the number of times an ip address has been logged
    switch (message->address_len) {
    case 4:
      if (is_whitelistv4(message->address4, server.config.whitelistv4.s_addr,
                         24)) {
        continue;
      }
      retval = ip_hashtable_insert(server.htable, &message->address4, AF_INET,
                                   message->timestamp);
      // printf("address: %d timestamp: %ld %ld, retval: %d\n", message->address4, message->timestamp, ts, retval);
      break;

    case 16:

      retval = ip_hashtable_insert(server.htable, &message->address6, AF_INET6,
                                   message->timestamp);
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

      switch (message->address_len) {
      case 4:

        if ((retval = ip_llist_push(server.banned_list, &message->address4, &ts,
                                    AF_INET)) < 0) {
          error_msg("Error pushing to banned list for logstring : %s : "
                    "Error Code %d\n",
                    iovecs[i].iov_base, retval);
          continue;
        }

#ifdef GRPC
        add_ipv4_to_request(gRPC_Client, request, message->address4);
        request_length++;
#else
        retval = bpf_map_update_elem(server.ipv4_ebpf_map, &message->address4,
                                     &values, BPF_NOEXIST);
#endif

        break;

      case AF_INET6:

        if ((retval = ip_llist_push(server.banned_list, &message->address6, &ts,
                                    AF_INET6)) < 0) {
          error_msg("Error pushing to banned list for logstring : %s : "
                    "Error Code %d\n",
                    iovecs[i].iov_base, retval);
          continue;
        }
#ifdef GRPC
        add_ipv6_to_request(gRPC_Client, request,
                            (uint8_t *)&message->address6);
        request_length++;
#else
        retval = bpf_map_update_elem(server.ipv6_ebpf_map, &message->address6,
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

        switch (message->address_len) {
        case 4:
          if ((retval = ip_hashtable_set(server.htable, &message->address4,
                                         AF_INET, server.config.limit - 1,
                                         message->timestamp)) < 0) {
            error_msg(
                "ip_hashtable set failed, Error code: %d, logstring: %s\n",
                retval);
          }
          break;
        case 16:
          if ((retval = ip_hashtable_set(server.htable, &message->address6,
                                         AF_INET6, server.config.limit - 1,
                                         message->timestamp)) < 0) {
            error_msg(
                "ip_hashtable set failed, Error code: %d, logstring: %s\n",
                retval);
          }
          break;
        default:
          break;
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
  struct timespec tspec = {.tv_sec = 0, .tv_nsec = targs->wakeup_interval};
  struct iovec iovecs[QUEUE_SIZE];
  // struct fips_bin_message* bin_messages; // TODO_BIN
  uint64_t rcv_count = 0, ban_count = 0, steal_count = 0, too_old=0;
  int recv_retval = 0;

#ifdef GRPC
  intervention_client_t *gRPC_Client;
  gRPC_Client = intervention_client_create();
#endif

  ipc_args_t *ipc_arg;
  int result = init_thread_ipc(targs, &ipc_arg);
  if (result == -1) {
    return &targs->retval;
  }

  int nr_cpus = libbpf_num_possible_cpus();
  __u64 values[nr_cpus];

  if (memset(&values, 0, sizeof(values)) == NULL) {
    error_msg("Memset error \n");
  }

  if (block_signals(false)) {
    error_msg("failed to block signals\n");
  }

  while (server.server_running) {

    // Message receiving dependent on ipc_type

    recv_retval = get_lines_ipc(targs, ipc_arg, iovecs);
    if (recv_retval < 0) {
      error_msg("uring_getlines failed with error code %d\n", recv_retval);
      targs->rcv_count = rcv_count;
      targs->ban_count = ban_count;
      targs->too_old = too_old;
      targs->steal_count = steal_count;
      targs->retval = EXIT_FAIL;
      return &targs->retval;
    }

    if (recv_retval == 0) {
      // printf("no more data\n");
      nanosleep(&tspec, NULL);
      continue;
    }

    rcv_count += QUEUE_SIZE;

#ifdef GRPC
    ban_clients(iovecs, recv_retval, &ban_count, &too_old, values, gRPC_Client);
#else
    ban_clients(iovecs, recv_retval, &ban_count, &too_old, values);
#endif

    return_lines_ipc(targs, ipc_arg, iovecs);
  }
// destroy gRPC Client
#ifdef GRPC
  intervention_client_destroy(gRPC_Client);
#endif

#ifdef ZERO_COPY
  printf("detach %d\n", fips_buf_detach(&fips_buf_thread_arg));
#endif
  deinit_thread_ipc(targs, ipc_arg);

  targs->rcv_count = rcv_count;
  targs->ban_count = ban_count;
  targs->too_old = too_old;
  targs->steal_count = steal_count;
  targs->retval = EXIT_SUCCESS;
  return &targs->retval;
}
