#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <isc/async.h>
#include <isc/buffer.h>
#include <isc/file.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/fips.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/stats.h>
#include <dns/types.h>
#include <dns/view.h>

#define IOVLEN 10

isc_result_t fips_dns_init(isc_mem_t *mctx, fips_buf_arg_t **envp){ 
  // isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_INFO, "fips_dns_init called");
  isc_result_t result = ISC_R_SUCCESS;
	REQUIRE(envp != NULL);
    if(*envp == NULL){

        fips_buf_arg_t *env = NULL;
        env = isc_mem_get(mctx, sizeof(*env));
        *env = (fips_buf_arg_t){
        };

        env->role = FIPS_WRITER;
        // env->shm_name = "/fips_zero_copy";
        // env->line_size = 200;
        // env->max_sqe_count = 1024;
        // env->line_count_exp = 22;
        // env->max_reader_count = 2;
        // env->max_reader_thread_count = 17;
        // env->max_segment_count = 17;
        // env->flags = FIPS_BUF_FLAG_OVERWRITE;

        int res = 0;
        char *config_file = getenv("FIPS_BUF_CONF");
        if (config_file)
          res=  fips_buf_init(env, config_file);
        else
          res= fips_buf_init(env, "/etc/fips_buf.conf");

        if(res != FIPS_BUF_SUCCESS){
          isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "couldn't init shared memory for fips logging");
          return ISC_R_NOMEMORY;
        }

        *envp = env;
    }
  return result;
  }

// init threads and write
isc_result_t fips_dns_write(dns_view_t *view,  isc_sockaddr_t *qaddr,
	    isc_sockaddr_t *dstaddr, dns_message_t *message){ 
  // isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "fips_dns_write called");
  // isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "querry: %.*s", message->sections[DNS_SECTION_QUESTION].head->length, message->sections[DNS_SECTION_QUESTION].head->ndata);

  static thread_local fips_buf_thread_arg_t fips_buf_thread_arg = {0};
  static thread_local int fips_buf_thread_arg_initialized = 0;

  if (fips_buf_thread_arg_initialized == 0){
      fips_buf_thread_arg_initialized = 1;
      fips_buf_thread_arg.process_arg = view->fipsenv;
      int res = fips_buf_attach(&fips_buf_thread_arg);
      if(res != FIPS_BUF_SUCCESS){
        isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "FIPS: couldn't attach thread to fips log buffer");
        return ISC_R_NOMEMORY;
      }
  }
    static thread_local struct iovec iov[IOVLEN];
    static thread_local int avail_iovs = 0;
    int ret = 0;

    if(avail_iovs < 1){
      ret = fips_get_write_buffer(&fips_buf_thread_arg, iov, IOVLEN);
      avail_iovs = IOVLEN;
    }
    
    if(ret != FIPS_BUF_SUCCESS){
        isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "FIPS: couldn't get write buffer");
    }
  
    fips_bin_message_t *bin_message = (fips_bin_message_t *)iov[IOVLEN-avail_iovs].iov_base;

    int family = isc_sockaddr_pf(qaddr);
    if (family == AF_INET){
      bin_message->address_len = 4;
      bin_message->address4 = qaddr->type.sin.sin_addr.s_addr;
    }else{
      bin_message->address_len = 16;
      memcpy(bin_message->address_arr6, qaddr->type.sin6.sin6_addr.s6_addr, 16);
    }

    time(&bin_message->timestamp);

    memcpy(&(bin_message->data), message->sections[DNS_SECTION_QUESTION].head->ndata, message->sections[DNS_SECTION_QUESTION].head->length);
    bin_message->data_len = message->sections[DNS_SECTION_QUESTION].head->length;
    iov[IOVLEN-avail_iovs].iov_len = sizeof(fips_bin_message_t)+bin_message->data_len;
    avail_iovs--;


    if(avail_iovs == 0){
      ret = fips_buf_write(&fips_buf_thread_arg, iov, IOVLEN);

      if (ret != FIPS_BUF_SUCCESS) {
          isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER, ISC_LOG_ERROR, "FIPS: commit write buffer");
      }
    }

  return ISC_R_SUCCESS;
}

// detach with force
isc_result_t fips_dns_detach(dns_view_t view){ 
  isc_log_write(dns_lctx,DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_MASTER , ISC_LOG_ERROR, "fips_dns_detach called");
  return 0;
}
