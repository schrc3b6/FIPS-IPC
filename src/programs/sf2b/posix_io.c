#include <simplefail2ban.h>
#include <stdio.h>

struct ipc_args_t {};

int init_thread_ipc(struct ban_targs_t *thread_args,
                    ipc_args_t **ipc_thread_arg) {

  int fd = (int64_t)thread_args->ipc_args;
  *ipc_thread_arg = (ipc_args_t*) fdopen(fd, "r");
  if (*ipc_thread_arg == NULL) {
    perror("fdopen");
    error_msg(" fd: \n", fd);
    return -1;
  }
  return 0;
}

int get_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t *ipc_thread_arg,
                  struct iovec *iovecs) {
  int recv_retval = 0;

  size_t n = LINEBUF_SIZE;
  n = iovecs[0].iov_len;
  int chars_read = 0;
  chars_read =
      getline((char **)&(iovecs[0].iov_base), &n, (FILE *)ipc_thread_arg);
  if (chars_read > 0) {
    iovecs[0].iov_len = chars_read;
    recv_retval = 1;
  } else if (chars_read < 0) {
    recv_retval = 0;
    long offset = ftell((FILE *) ipc_thread_arg);
    fclose((FILE *) ipc_thread_arg);
    ipc_thread_arg = fopen(server.config.logfile , "r");
    fseek((FILE *)ipc_thread_arg, offset, SEEK_SET);
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
  int fd;
  if ((fd = open(server.config.logfile, O_RDONLY, 0644)) == -1) {
    perror("open failed");
    return -1;
  }
  thread_args[0].ipc_args = (void *)fd;
  return 0;
}

bool cleanup_ipc(struct ban_targs_t **thread_args) {

  close((int)(*thread_args)[0].ipc_args);
  return false;
}
