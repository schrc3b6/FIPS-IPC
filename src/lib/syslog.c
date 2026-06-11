#include "io_ipc.h"
// #include <asm/unistd_64.h>
#include <bits/pthreadtypes.h>
#include <bits/types/struct_iovec.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <fips_syslog.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>

#define OPEN_MODE O_WRONLY | O_CREAT | O_TRUNC | O_APPEND
#define OPEN_PERM 0644

// shared memory is initialized on openlog function
static struct shmrbuf_writer_arg_t *writer_struct;

// shared memory argument struct for zero copy api
fips_buf_arg_t arg = {0};


// Sets the number of shared memory segments.
// BIND uses one thread for start log messages, which is not used for message logging.
// In addition, BIND creates one message logging thread per CPU core used.
// e.g. BIND uses 6 CPU cores, so 7 threads are created, thereof 6 are used for message logging.
#define SEGMENT_COUNT 17

#define LINE_SIZE 254
#define LINE_COUNT 1000000

#define BUFFER_SIZE 16

// counts the number of logging threads
// is used to assign a unique segment in the shared memory to each thread
_Atomic int thread_counter = 0;

// counts the number of missed write operations
// to shared memory due to slow reader
_Atomic long missed_writes = 0;

// atexit handler to print the number of missed writes
void print_missed_writes(){
    fprintf(stderr, "Missed writes: %ld\n", missed_writes);
}

/**
 * @brief Writes syslog logging messages to a shared memory area using the FIPS
 * API
 *
 * @param pri
 * @param fmt
 * @param ...
 */
void syslog(int pri, const char *fmt, ...){
    int length = 0;
    // return;
    #ifndef ZERO_COPY
    static __thread int thread_segment = -1;

    // numbers the logging threads at the first call in order to obtain
    // unique thread-shared memory segment assignments
    if (thread_segment == -1){
        thread_segment = thread_counter++;
        }

    // check that thread_segment is not greater than SEGMENT_COUNT
    if(thread_segment > SEGMENT_COUNT - 1){
        fprintf(stderr, "Segment ID exceeds number of available segments\n");
        exit(EXIT_FAILURE);
    }

    /**
    * Used for buffering logs until BUFFER_SIZE is reached and whole vector
    * structure is written to shared memory
    * BUG: So far no function that checks whether there are any logs left in the
    * buffer. This does not guarantee that all logs are written to the shared
    * memory.
    */
    #ifdef WRITEV
    
    static __thread int iovec_counter = 0;
    static __thread char local_buf[BUFFER_SIZE][LINE_SIZE] = {'\0'};
    static __thread struct iovec iovec_buffer[BUFFER_SIZE] = {0};

    if (iovec_counter < BUFFER_SIZE) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(local_buf[iovec_counter], LINE_SIZE, fmt, args);
        va_end(args);

        length = strlen(local_buf[iovec_counter]);
        local_buf[iovec_counter][length] = '\n';
        iovec_buffer[iovec_counter].iov_base = &local_buf[iovec_counter];
        iovec_buffer[iovec_counter].iov_len = length + 1;

        ++iovec_counter;
    } else {
        fprintf(stderr, "%d\n", iovec_counter);
        int elements_writev = shmrbuf_writev(writer_struct, iovec_buffer,
                                            iovec_counter, thread_segment);
        if ((elements_writev < 0)) {
        fprintf(stderr, "Error on writev with error code: %d\n", elements_writev);
        exit(EXIT_FAILURE);
        }
        iovec_counter = 0;
    }

    #endif
    
    // Writes every log line from Syslog directly to the shared memory
    #ifndef WRITEV
        char local_buf[LINE_SIZE] = {'\0'};
        va_list args;
        va_start (args, fmt);
        vsnprintf(local_buf, LINE_SIZE, fmt, args);
        va_end(args);
        int wsize;
        length = strlen(local_buf);
        local_buf[length] = '\n';
        // local_buf[length] = '\0';
        // if(length > LINE_SIZE - 2){
        //     local_buf[length - 1] = '\n';
        //     local_buf[length] = '\0';
        // }
        if((wsize = shmrbuf_write(writer_struct, (void *) local_buf, LINE_SIZE, thread_segment)) < 0){
            // perror("write process in shared memory failed");
            missed_writes++;
        } else {
            // fprintf(stderr, "wrote %d elements: %s\n", wsize, buffer);
            if(!memset(local_buf, '\0', LINE_SIZE)){
                perror("Error on resetting buffer");
            };
        }
    #endif

    #endif

    #ifdef ZERO_COPY

    static __thread int thread_segment = -1;

    // numbers the logging threads at the first call in order to obtain
    // unique thread-shared memory segment assignments
    static __thread fips_buf_thread_arg_t fips_buf_thread_arg = {0};

    if (thread_segment == -1){
        fips_buf_thread_arg.process_arg = &arg;
        printf("attach status %d from thread segment %d\n", fips_buf_attach(&fips_buf_thread_arg), thread_segment);
        printf("segment_header %p segment %d\n", &((fips_buf_segment_header_t*)fips_buf_thread_arg.current_segment)->writer.head_offset, ((fips_buf_segment_header_t*)fips_buf_thread_arg.current_segment)->index);
        thread_segment=0;
        fflush(stdout);
    }

    static __thread int buffer_position = 0;

    static __thread struct iovec iov[BUFFER_SIZE];
    int ret = 0;

    if(buffer_position == 0){
      ret = fips_get_write_buffer(&fips_buf_thread_arg, iov, BUFFER_SIZE);
      if(ret != FIPS_BUF_SUCCESS){
          printf("get write buffer failed %d thread_index: %d \n", ret, fips_buf_thread_arg.thread_index);
          exit(EXIT_FAILURE);
      }
    }

    #ifdef FIPS_BUF_USE_VSNPRINTF
    va_list args;
    va_start (args, fmt);
    length = vsnprintf(iov[0].iov_base, iov[0].iov_len, fmt, args);
    va_end(args);
    #else
    va_list args;
    va_start (args, fmt);
    size_t str_pos = 0;
    char* arg=NULL;
    size_t bytes_written=0;
    ((char *)iov[buffer_position].iov_base)[0] = '\0';    
    while(str_pos < LINE_SIZE && fmt[str_pos]!=0)
    {
      if (fmt[str_pos]=='%'){
        arg=va_arg(args, char *);
        size_t bytes_to_copy = strnlen(arg,LINE_SIZE-bytes_written);
        memcpy(iov[buffer_position].iov_base+bytes_written, arg, bytes_to_copy);
        bytes_written+=bytes_to_copy;
      }
      str_pos++;
    }
    va_end(args);
    length=bytes_written;
    #endif
    
    if(length > LINE_SIZE - 2){
            length = LINE_SIZE - 2;
        }
       
    ((char *)iov[buffer_position].iov_base)[length] = '\n';
    ((char *)iov[buffer_position].iov_base)[length + 1] = '\0';    
    iov[buffer_position].iov_len = length + 1;

    buffer_position = (buffer_position + 1) & (BUFFER_SIZE-1); 

    if (buffer_position == 0) {
      ret = fips_buf_write(&fips_buf_thread_arg, iov, BUFFER_SIZE);
      if (ret != FIPS_BUF_SUCCESS) {
        fprintf(stderr, "write failed %d\n", ret);
      }
    }

    #endif
        

}


void openlog(const char *tag, int options, int facility){

    // Implementation of shared memory with memcopy
    #ifndef ZERO_COPY
    int atexit_handler_value;
    atexit_handler_value = atexit(print_missed_writes);
    if(atexit_handler_value != 0){
        perror("atexit() function registration failed");
        exit(EXIT_FAILURE);
    }
    int retval;
    if((writer_struct = (struct shmrbuf_writer_arg_t *) calloc(sizeof(struct shmrbuf_writer_arg_t), 1)) == NULL){
        perror("calloc failed");
        exit(EXIT_FAILURE);
    };

    char path[] = "./udpsvr.log";
    int logfile_ptr;
    if((logfile_ptr = open(path, OPEN_MODE, OPEN_PERM)) < 0){
        perror("opening logfile failed");
    }
    close(logfile_ptr);

    writer_struct->line_count = LINE_COUNT;
    writer_struct->line_size = LINE_SIZE;
    writer_struct->segment_count = SEGMENT_COUNT;
    writer_struct->reader_count = 2;
    writer_struct->shm_key = path;
    writer_struct->flags = SHMRBUF_REATT | SHMRBUF_FRCAT | SHMRBUF_OVWR;


    if((retval = shmrbuf_init((union shmrbuf_arg_t *)writer_struct, SHMRBUF_WRITER)) != IO_IPC_SUCCESS){
        fprintf(stderr, "Error on initilization of shared memory");
        shmrbuf_finalize((union shmrbuf_arg_t *) writer_struct, SHMRBUF_WRITER);
        exit(EXIT_FAILURE);
    }
    else{
        fprintf(stdout, "shmrbuf initilization succesful!\n");
    }
    #endif

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    // Implementation of shared memory with zero copy
    #ifdef ZERO_COPY

    arg.role = FIPS_WRITER;
    // arg.shm_name = "/fips_zero_copy";
    // arg.line_size = LINE_SIZE;
    // arg.max_sqe_count = 1024;
    // arg.line_count_exp = 22;
    // arg.max_reader_count = 2;
    // arg.max_reader_thread_count = 17;
    // arg.max_segment_count = 17;
    // arg.flags = FIPS_BUF_FLAG_OVERWRITE;
    char *config_file = getenv("FIPS_BUF_CONF");
    if (config_file)
      printf("init %d\n", fips_buf_init(&arg, config_file));
    else
      printf("init %d\n", fips_buf_init(&arg, "/etc/fips_buf.conf"));
    // fprintf(stdout, "fips buf init from openlog: %d\n", fips_buf_init(&arg));
    printf("start segment: %p, end segment %p\n",arg.header, APPLY_POINTER_OFFSET(arg.header,FIPS_BUF_GET_SEGMENT_HEADER(arg.header, 17)));

    #endif




}








