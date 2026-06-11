#include <simplefail2ban.h>


struct ipc_args_t {
  //this needs to stay first
  fips_buf_thread_arg_t fips_thread_arg;
  uint64_t tag;
};

int init_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t ** ipc_thread_arg){
    *ipc_thread_arg = calloc(1, sizeof(ipc_args_t));
    (*ipc_thread_arg)->fips_thread_arg.process_arg = thread_args->arg;
    printf("attach %d\n", fips_buf_attach(&(*ipc_thread_arg)->fips_thread_arg));
    return 0;
}

int get_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs) {
  int ret = fips_buf_read((fips_buf_thread_arg_t*)ipc_thread_arg, iovecs, QUEUE_SIZE, &(ipc_thread_arg->tag), 0);

  if (ret != FIPS_BUF_SUCCESS) {
    return 0;
  }

  return QUEUE_SIZE;
}

int return_lines_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg, struct iovec *iovecs){
        int ret = fips_buf_return((fips_buf_thread_arg_t*)ipc_thread_arg, ipc_thread_arg->tag);
        if (ret != FIPS_BUF_SUCCESS) {
          fprintf(stdout, "fips_buf_return failed: %d\n", ret);
        }
  return 0;
}


int deinit_thread_ipc(struct ban_targs_t *thread_args, ipc_args_t * ipc_thread_arg){
    printf("detach %d\n", fips_buf_detach((fips_buf_thread_arg_t*)ipc_thread_arg));
    return 0;
}

int init_ipc(struct ban_targs_t *thread_args) {
  fips_buf_arg_t *arg = calloc(1, sizeof(fips_buf_arg_t));

  arg->role = FIPS_READER;
  // arg->shm_name = "/fips_zero_copy";
  // arg->line_size = 200;
  // arg->max_sqe_count = 1024;
  // arg->line_count_exp = 22;
  // arg->max_reader_count = 2;
  // arg->max_reader_thread_count = 17;
  // arg->max_segment_count = 17;
  // arg->flags = FIPS_BUF_FLAG_OVERWRITE;
  char *config_file = getenv("FIPS_BUF_CONF");
  if (config_file)
    printf("init %d\n", fips_buf_init(arg, config_file));
  else
    printf("init %d\n", fips_buf_init(arg, "/etc/fips_buf.conf"));

  for (int i = 0; i < server.config.thread_count; i++) {
    thread_args[i].arg = arg;
  }
  return 0;
}

bool cleanup_ipc(struct ban_targs_t **thread_args) {

  fips_buf_destroy((fips_buf_arg_t*) *thread_args, FIPS_BUF_FLAG_FORCE);
  free(*thread_args);
  return false;
}
