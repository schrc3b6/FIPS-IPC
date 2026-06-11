#include <simplefail2ban.h>

struct ipc_args_t {
  uint8_t lower_seg;
  uint8_t upper_seg;
};

int init_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t ** ipc_thread_arg){


    ipc_args_t *ipc_arg = (ipc_args_t*) ipc_thread_arg;
    uint8_t seg_count, upper_seg = 0, lower_seg = 0;
    struct shmrbuf_reader_arg_t *shm_arg = NULL;
    shm_arg = (struct shmrbuf_reader_arg_t *)thread_args->ipc_args;

    // Terminate unneeded threads returen, if there are more threads than
    // semgente to be read out
    if (thread_args->thread_id >= shm_arg->global_hdr->segment_count) {
      thread_args->retval = RETURN_SUCC;
      return -1;
    }

    // Determine the ringbuffer segments for the thread, as well as the range
    // for workload stealing.

    seg_count = shm_arg->global_hdr->segment_count / server.config.thread_count;
    int remainder = shm_arg->global_hdr->segment_count % server.config.thread_count;
    int segments_per_thread[server.config.thread_count + 1];
    segments_per_thread[0] = 0;

    for (int i = 0; i < server.config.thread_count; ++i) {
      segments_per_thread[i + 1] =
          (i < remainder) ? (seg_count + 1) : seg_count;
    }

    for (int i = 0; i <= thread_args->thread_id; ++i) {
      lower_seg += segments_per_thread[i];
      upper_seg += segments_per_thread[i + 1];
    }

    printf("lower segment of thread %d: %d\n", thread_args->thread_id, lower_seg);
    printf("upper segment of thread %d: %d\n", thread_args->thread_id, upper_seg);

  ipc_arg->lower_seg = lower_seg;
  ipc_arg->upper_seg = upper_seg;

  return 0;
}


int get_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs) {
  int recv_retval = 0;
    struct shmrbuf_reader_arg_t *shm_arg = (struct shmrbuf_reader_arg_t *)thread_args->ipc_args;
    ipc_args_t* ipc_arg = ((ipc_args_t*) &ipc_thread_arg);

      if ((recv_retval =
               shmrbuf_readv_rng(shm_arg, iovecs, QUEUE_SIZE, LINEBUF_SIZE,
                                 ipc_arg->lower_seg, ipc_arg->upper_seg, 0)) > 0) {

        for (int i = 0; i < recv_retval; i++) {
          uint16_t len = iovecs[i].iov_len;
          char *str = (char *)iovecs[i].iov_base;
          while (len-- > 0) {
            if (str[len] == '\n') {
              str[len] = '\0';
              break;
            }
          }
        }
      }  
  return recv_retval;
}

int return_lines_ipc(struct ban_targs_t *thread_args,
                     ipc_args_t *ipc_thread_arg, struct iovec *iovecs) {
  return 0;
}

int deinit_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg){
    return 0;
}

int init_ipc(struct ban_targs_t *thread_args) {

  struct shmrbuf_reader_arg_t *rbuf_arg = NULL;
  int retval;
  if ((rbuf_arg = (struct shmrbuf_reader_arg_t *)calloc(
           sizeof(struct shmrbuf_reader_arg_t), 1)) == NULL) {
    perror("calloc failed");
    return -1;
  }

  rbuf_arg->shm_key = server.config.shm_key;

  if ((retval = shmrbuf_init((union shmrbuf_arg_t *)rbuf_arg,
                             SHMRBUF_READER)) != IO_IPC_SUCCESS) {
    if (retval > 0) {
      perror("shm_rbuf_init failed");
    } else {
      fprintf(stderr, "shm_rbuf_init failed : error code %d\n", retval);
    }
    return -1;
  }
  printf("shmrbuf succesful with %d\n", retval);
  for (int i = 0; i < server.config.thread_count; i++) {
    thread_args[i].ipc_args = (void *)rbuf_arg;
  }
  return 0;
}


bool cleanup_ipc(struct ban_targs_t **thread_args) {

  int retval;
  if ((retval =
           shmrbuf_finalize((union shmrbuf_arg_t *)(*thread_args)[0].ipc_args,
                            SHMRBUF_READER)) != IO_IPC_SUCCESS) {
    fprintf(stderr, "shmrbuf_finalize failed with error code: %d\n", retval);
    return true;
  }

  free((*thread_args)[0].ipc_args);

  return false;
}
