#include <simplefail2ban.h>

struct ipc_args_t {
};

int init_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t ** ipc_thread_arg) {
  return 0;
}

int get_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs) {
  int recv_retval = 0;
	struct file_io_t * file_arg = NULL;
  file_arg = (struct file_io_t *) thread_args->ipc_args;
    if ((recv_retval = uring_getlines(file_arg, iovecs, QUEUE_SIZE,
                                      LINEBUF_SIZE)) > 0) {
      for (int i = 0; i < recv_retval; i++) {
        ((char *)iovecs[i].iov_base)[iovecs[i].iov_len - 1] = '\0';
      }
    } 
  return recv_retval;
}

int return_lines_ipc(struct ban_targs_t *thread_args,
                     ipc_args_t *ipc_thread_arg, struct iovec *iovecs) {
  return 0;
}

int init_ipc(struct ban_targs_t *thread_args) {

  struct file_io_t *file_io_args = NULL;
  if ((file_io_args =
           (struct file_io_t *)calloc(sizeof(struct file_io_t), 1)) == NULL) {
    perror("calloc failed");
  }

  else if ((file_io_args->logfile_fd =
                open(server.config.logfile, O_RDONLY, 0644)) == -1) {
    perror("open failed");
  }

  else if (io_uring_queue_init(2, &file_io_args->ring, 0) == -1) {
    perror("ic_uring_queue_init failed");
  }

  else {
    thread_args[0].ipc_args = (void *)file_io_args;
    return 0;
  }

  return -1;
}

int deinit_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg){
    return 0;
}

bool cleanup_ipc(struct ban_targs_t **thread_args) {

  io_uring_queue_exit(&((struct file_io_t *)(*thread_args)[0].ipc_args)->ring);

  if (close(((struct file_io_t *)(*thread_args)[0].ipc_args)->logfile_fd) < 0) {
    perror("close");
    return true;
  }

  free((*thread_args)[0].ipc_args);

  return false;
}

