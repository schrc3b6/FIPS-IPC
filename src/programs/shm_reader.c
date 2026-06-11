#include <arpa/inet.h>
#include <bits/types/struct_iovec.h>
#include <sched.h>
#include <signal.h>
// #include <linux/io_uring.h>
#include <linux/time_types.h>
#include <liburing/io_uring.h>
#include <shm_ringbuf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <liburing.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <argp.h>
#include <time.h>
#include <unistd.h>
#include <fips_buf.h>


#define NUM_THREADS 17
#define BUF_SIZE 10
#define RING_SIZE 10
#ifdef BIN_TO_STRING
#define LINE_SIZE 200
#else
#define LINE_SIZE 254
#endif
// #define ZERO_COPY

volatile sig_atomic_t do_shutdown = 0;

struct thread_args{
    struct shmrbuf_reader_arg_t *reader_struct;
    int thread_id;
    struct io_uring ring;
    int file_id;
    struct arguments *cmd_args;
    int *segment_range;
    fips_buf_arg_t *arg;
};

// defines the strategy for using io_urings 
enum IO_URING_MODE {
    // read a single log message from shared memory, write it to the io_uring and submit the ring instantly
    SINGLE_READ_SINGLE_WRITE,
    // read a single log message from shared memory, buffer it in io_uring and submit the ring when it's full
    SINGLE_READ_BATCH_WRITE, 
    // read a batch of log messages from shared memory, write it to the io_uring and submit the ring instantly 
    BATCH_READ_SINGLE_WRITE,
    // read a batch of log messages from shared memory, buffer it in the io_uring and submit the ring when it's full
    BATCH_READ_BATCH_WRITE
};

/**
 * @brief Signal handler that changes the global variable that interrupts the
 * reading loop
 */
void signal_handler(int signum, siginfo_t *info, void *extra)
{
    printf("Handler thread ID: %d\n", getpid());
    do_shutdown = 1;
}

void set_signal_handler(void)
{
    struct sigaction action;
    action.sa_flags = SA_SIGINFO;     
    action.sa_sigaction = signal_handler;
    sigemptyset(&action.sa_mask);
    // action.sa_flags = SA_RESTART;
    sigaction(SIGINT, &action, NULL);
}


const char *argp_program_version = "SHM2File v0.1";
static char doc[] = "This is a simple reader writing shared memory content asynchronously to a file";
static char args_doc[] = " ";

static struct argp_option options[] = {
    {"path", 'p', "PATH", 0, "Path to the file in which the messages are to be written."},
    {"threads", 't', "THREAD_NUMBER", 0, "Number of reader threads."},
    {"iomode", 'i', "IO_URING_MODE", 0, "Sets the io_uring write mode."},
    {"help", 'h', 0, 0, "Overview of used command line arguments."},
    {0}
};

struct arguments{
    char *path;
    int thread_number;
    int io_uring_mode;
    struct shmrbuf_reader_arg_t *reader_struct;
};

/**
 * @brief Manages the input handling of the command line. The user can specify
 * the path of the log file and the number of shared memory segments, which also
 * have default values.
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state){

    struct arguments *arguments=state->input;
    switch(key){
        case 'p':
            arguments->path = arg;
            break;

        case 't':
            arguments->thread_number = atoi(arg);
            if((arguments->thread_number < 0) || (arguments->thread_number > 17)){
                fprintf(stderr, "Number of segments not in a valid range. Is now set to 1.");
                arguments->thread_number = 1;
            }
            break;

        case 'i':
            if(atoi(arg) == 0){
                arguments->io_uring_mode = SINGLE_READ_SINGLE_WRITE;
            }
            else if(atoi(arg) == 1){
                arguments->io_uring_mode = SINGLE_READ_BATCH_WRITE;
            }
            else if(atoi(arg) == 2){
                arguments->io_uring_mode = BATCH_READ_SINGLE_WRITE;
            }
            else if(atoi(arg) == 3){
                arguments->io_uring_mode = BATCH_READ_BATCH_WRITE;
            }

            break;

        case 'h':
            {
            #ifndef ZERO_COPY
            int retval = shmrbuf_finalize((union shmrbuf_arg_t*) arguments->reader_struct, SHMRBUF_READER);
            if(retval == IO_IPC_SUCCESS){
                fprintf(stderr, "Reader succesful detached from shared memory\n");
            }else {
                fprintf(stderr, "Error on detaching shared memory: %d\n", retval);
            };
            #endif
            argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
            break;
            }
        case ARGP_KEY_ARG:
            return 0;
        
        default:
            return ARGP_ERR_UNKNOWN;

    }

    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};


/**
 * @brief Function is called by the reader threads. Reads individual elements
 * from the shared memory area and passes them to the thread-specific io_uring
 * structure, which immediately submits the submission queue for each element.
 *
 * @param args: pointer to struct with necessary thread arguments
 * @param sqe: pointer to submission queue of io_uring structure
 * @param cqe: pointer to completion queue of io_uring structure
 * @param file_id: file descriptor for the target file
 */
void single_read_single_write(struct thread_args *args,
                              struct io_uring_sqe *sqe,
                              struct io_uring_cqe *cqe,
                              struct arguments *cmd_args) {
  

  #ifndef ZERO_COPY
  // size of read bytes of shared memory segment
  int rsize;
  int line_size = args->reader_struct->global_hdr->line_size;
  char rbuf[line_size];

  int lower_seg = 0, upper_seg = 0;
  for (int i = 0; i<=args->thread_id; ++i){
			lower_seg += args->segment_range[i];
			upper_seg += args->segment_range[i+1];
		}

  printf("lower segment of thread %d: %d\n", args->thread_id, lower_seg);
  printf("upper segment of thread %d: %d\n", args->thread_id, upper_seg);
    
  // loop runs until SIGINT signal is received
  // an element is read from the shared memory area, written to the submission
  // queue and submitted immediately.
  while (!do_shutdown) {
    memset(rbuf, '\0', line_size);

    if ((rsize = shmrbuf_read_rng(args->reader_struct, rbuf, line_size, lower_seg, upper_seg, false)) < 0) {
      fprintf(stderr, "reading process failed %d\n", rsize);
      EXIT_FAILURE;
    } else {

      if (rsize == 0) {
        continue;
      } else {
        sqe = io_uring_get_sqe(&args->ring);
        if (sqe == NULL) {
          fprintf(stderr, "Error on submission queue");
        }
        int length = strlen(rbuf);
        rbuf[length - 1] = '\n';
        io_uring_prep_write(sqe, args->file_id, rbuf, length, -1);
        
        io_uring_submit(&args->ring);

        io_uring_wait_cqe(&args->ring, &cqe);
        io_uring_cqe_seen(&args->ring, cqe);
      }
    }
  }
  io_uring_queue_exit(&args->ring);

  #endif
}

/**
 * @brief Function is called by the reader threads. Reads individual elements
 * from the shared memory area and transfers them to the thread-specific
 * io_uring, which first fills the ring structure and only then submits it.
 *
 * @param args: pointer to struct with necessary thread arguments
 * @param sqe: pointer to submission queue of io_uring structure
 * @param cqe: pointer to completion queue of io_uring structure
 * @param file_id: file descriptor for the target file
 */
void single_read_batch_write(struct thread_args *args,
                             struct io_uring_sqe *sqe,
                             struct io_uring_cqe *cqe) {

    int rsize;
    int line_size = args->reader_struct->global_hdr->line_size;

    int lower_seg = 0, upper_seg = 0;
    for (int i = 0; i<=args->thread_id; ++i){
			lower_seg += args->segment_range[i];
			upper_seg += args->segment_range[i+1];
		}

    printf("lower segment of thread %d: %d\n", args->thread_id, lower_seg);
    printf("upper segment of thread %d: %d\n", args->thread_id, upper_seg);

    // initialisation of an intermediate buffer of the size "number of ring
    // elements" x "size of log messages"
    char buffer_array[BUF_SIZE][line_size];

    // Used for the references to the corresponding array index.
    // Is used to assign submissions and completions in io_uring
    int array_idx[BUF_SIZE];
    // Contains the buffer positions that are free and can be reused in places
    // that are greater than idx.
    int buffer_position[BUF_SIZE];
    int idx = 0;
    // initialisation of the array_idx and buffer_position arrays
    for (int i = 0; i<BUF_SIZE; i++){
        array_idx[i] = i;
        buffer_position[i] = i;
    }
    // Pointer contains position to element in array_idx as reference for the
    // submission element
    int *data;
    // actual position to the local buffer
    int buffer_idx = 0;

    // run until shutdown variable is set to true through SIGINT    
    while(!do_shutdown){
        
        while(true){
            
            // If idx equals BUF_SIZE, the local buffer is completely filled 
            // and cannot hold any further elements. Completion queue elements 
            // must first be processed and memory must be released in the local buffer
            if(idx == (BUF_SIZE)){
                break;
            }
            buffer_idx = buffer_position[idx];

            if((rsize = shmrbuf_read_rng(args->reader_struct, buffer_array[buffer_idx], line_size, lower_seg, upper_seg, false)) < 0){
                    fprintf(stderr, "reading process failed %d\n", rsize);
                    exit(EXIT_FAILURE);
            }
            // if nothing to read continue in loop
            else if (rsize == 0) {
                break;
            }
            
            // get free submission queue element
            // on error break first and try to consume element in second loop
            sqe = io_uring_get_sqe(&args->ring);
            if(sqe == NULL){
                fprintf(stderr, "Error on submission queue");
                break;
            }
            io_uring_prep_write(sqe, args->file_id, buffer_array[buffer_idx], strlen(buffer_array[buffer_idx]), -1);
            // save the current position in the sqe element so that it can be reassigned after completion
            io_uring_sqe_set_data(sqe, &array_idx[buffer_idx]);
            
            // if(args->thread_id == 0) printf("data submission: %d\n", array_idx[buffer_idx]);
            ++idx;
        }

        // submit all elements in the submission queue
        io_uring_submit(&args->ring);
        
        // consumption loop of completion queue
        while(true){
            // Checks if a completion event is available (doesnt wait like
            // io_uring_wait function). If not break loop and try to write new log
            // messages to the submission queue
            int status = io_uring_peek_cqe(&args->ring, &cqe);
            if (status == -EAGAIN) {
              break;
            }

            --idx;
            // save buffer position of completed event
            data = io_uring_cqe_get_data(cqe);
            // if(args->thread_id == 0) printf("data completion: %d\n", *data);
            // if(args->thread_id == 0) printf("idx: %d\n", idx);
            // write buffer position of completed event to buffer_position
            // so that it can be reused
            buffer_position[idx] = *data;
            
            // if completion event is available, mark as seeen to free the place
            io_uring_cqe_seen(&args->ring, cqe);
            
            if(idx == 0){
                break;
            }
        }
   
    }
    // if loop is stoped clean up io_uring structures
    io_uring_queue_exit(&args->ring);

}


void batch_read_single_write(struct thread_args *args, 
                             struct io_uring_sqe *sqe,
                             struct io_uring_cqe *cqe) {


  #ifndef ZERO_COPY
  int rsize;
  int line_size = args->reader_struct->global_hdr->line_size;

  int lower_seg = 0, upper_seg = 0;
  for (int i = 0; i<=args->thread_id; ++i){
			lower_seg += args->segment_range[i];
			upper_seg += args->segment_range[i+1];
		}

  printf("lower segment of thread %d: %d\n", args->thread_id, lower_seg);
  printf("upper segment of thread %d: %d\n", args->thread_id, upper_seg);

  char rbuf[BUF_SIZE][line_size];

    struct iovec iovec_buf[BUF_SIZE];
    for (int i = 0; i<BUF_SIZE; i++){
        iovec_buf[i].iov_base = &rbuf[i];
        iovec_buf[i].iov_len = line_size;
    }
    int buf_counter = 0;

    while (!do_shutdown) {

      if ((rsize = shmrbuf_readv_rng(args->reader_struct, iovec_buf, BUF_SIZE, line_size, lower_seg, upper_seg, false)) <
          0) {
        fprintf(stderr, "reading process failed %d\n", rsize);
        exit(EXIT_FAILURE);
      }
      // if nothing to read continue in loop
      else if (rsize == 0) {
        sched_yield();
        continue;
      } else {
        // printf("rsize: %d\n", rsize);
        for (int i = 0; i < BUF_SIZE; i++) {
          iovec_buf[i].iov_len = strlen(iovec_buf[i].iov_base);
        }
        sqe = io_uring_get_sqe(&args->ring);
        io_uring_prep_writev(sqe, args->file_id, iovec_buf, rsize, -1);
        
        io_uring_submit(&args->ring);
        io_uring_wait_cqe(&args->ring, &cqe);
        io_uring_cqe_seen(&args->ring, cqe);
      }
    }
    io_uring_queue_exit(&args->ring);

    #endif

    #ifdef ZERO_COPY
    
    fips_buf_thread_arg_t fips_buf_thread_arg = {0};
    fips_buf_thread_arg.process_arg = args->arg;
    printf("attach %d\n", fips_buf_attach(&fips_buf_thread_arg));

    


    struct iovec iov[BUF_SIZE];
    uint64_t tag;

    while (!do_shutdown) {
        int ret = fips_buf_read(&fips_buf_thread_arg, iov, BUF_SIZE, &tag, 0);
        
        if (ret != FIPS_BUF_SUCCESS) { 
            // fprintf(stderr, "fips_buf_read failed: %d segment %d \n", ret, fips_buf_thread_arg.assignment->start_segment);
            // fflush(stderr);
            sched_yield(); // TODO sched_yield correct here?
            continue;
        }
            sqe = io_uring_get_sqe(&args->ring);
            if (sqe == NULL) {
              fprintf(stderr, "Error on submission queue");
            }
            io_uring_prep_writev(sqe, args->file_id, iov, BUF_SIZE, -1);  
            io_uring_submit(&args->ring);   
            io_uring_wait_cqe(&args->ring, &cqe);
            io_uring_cqe_seen(&args->ring, cqe);
            ret = fips_buf_return(&fips_buf_thread_arg, tag);
            if (ret != FIPS_BUF_SUCCESS) {
                fprintf(stderr, "fips_buf_return failed: %d\n", ret);
            }
    }
  
    io_uring_queue_exit(&args->ring);
    printf("detach %d\n", fips_buf_detach(&fips_buf_thread_arg));

  #endif

    
}

void batch_read_batch_write(struct thread_args *args, 
                             struct io_uring_sqe *sqe,
                             struct io_uring_cqe *cqe){

    struct timespec sleeptime = {0,2000000};
    #ifndef ZERO_COPY     
    int rsize;
    int line_size = args->reader_struct->global_hdr->line_size;

    int lower_seg = 0, upper_seg = 0;
    for (int i = 0; i<=args->thread_id; ++i){
			lower_seg += args->segment_range[i];
			upper_seg += args->segment_range[i+1];
		}

    printf("lower segment of thread %d: %d\n", args->thread_id, lower_seg);
    printf("upper segment of thread %d: %d\n", args->thread_id, upper_seg);

    // initialisation of an intermediate buffer of the size "number of ring
    // elements" x "size of log messages"
    char buffer_array[RING_SIZE][BUF_SIZE][line_size];

    // Used for the references to the corresponding array index.
    // Is used to assign submissions and completions in io_uring
    int array_idx[RING_SIZE];
    // Contains the buffer positions that are free and can be reused in places
    // that are greater than idx.
    int buffer_position[RING_SIZE];
    int idx = 0;
    // initialisation of the array_idx and buffer_position arrays
    for (int i = 0; i<RING_SIZE; i++){
        array_idx[i] = i;
        buffer_position[i] = i;
    }
    // Pointer contains position to element in array_idx as reference for the
    // submission element
    int *data;
    // actual position to the local buffer
    int buffer_idx = 0;

    struct iovec iovec_buf[RING_SIZE][BUF_SIZE];
    for (int i = 0; i<RING_SIZE; i++){
        for(int j = 0; j<BUF_SIZE;j++){
            iovec_buf[i][j].iov_base = &buffer_array[i][j];
            iovec_buf[i][j].iov_len = line_size;
        }
    }

    // run until shutdown variable is set to true through SIGINT    
    while(!do_shutdown){
        // fill submission queue
        while(true){

            // If idx equals BUF_SIZE, the local buffer is completely filled 
            // and cannot hold any further elements. Completion queue elements 
            // must first be processed and memory must be released in the local buffer
            if(idx == (RING_SIZE)){
                break;
            }
            buffer_idx = buffer_position[idx];
          
            if((rsize = shmrbuf_readv_rng(args->reader_struct, iovec_buf[buffer_idx], BUF_SIZE, line_size, lower_seg, upper_seg, false)) < 0){
                    fprintf(stderr, "reading process failed %d\n", rsize);
                    exit(EXIT_FAILURE);
            }
            // if nothing to read continue in loop
            else if (rsize == 0) {
                // TODO: sched_yield?
                break;
            }
            // get free submission queue element
            // on error break first and try to consume element in second loop
            sqe = io_uring_get_sqe(&args->ring);
            if(sqe == NULL){
                fprintf(stderr, "Error on submission queue");
                break;
            }
            
            for(int j=0;j<BUF_SIZE;j++){
                iovec_buf[buffer_idx][j].iov_len = strlen(iovec_buf[buffer_idx][j].iov_base);
                }
            io_uring_prep_writev(sqe, args->file_id, iovec_buf[buffer_idx], rsize, -1);
            // save the current position in the sqe element so that it can be reassigned after completion
            io_uring_sqe_set_data(sqe, &array_idx[buffer_idx]);
            
            ++idx;
            
        }

        // if io_uring is filled, submission takes place
        io_uring_submit(&args->ring);
        
        // consumption loop of completion queue
        while(true){
          // checks if a completion event is available (doesnt wait like
          // io_uring_wait function) if not break loop and try to write new log
          // messages to the submission queue
          int status = io_uring_peek_cqe(&args->ring, &cqe);
          if (status == -EAGAIN) {
            // sched_yield ?
            break;
            }

            --idx;
            // save buffer position of completed event
            data = io_uring_cqe_get_data(cqe);

            buffer_position[idx] = *data;
            
            // if completion event is available, mark as seeen to free the place
            io_uring_cqe_seen(&args->ring, cqe);
            
            if(idx == 0){
                break;
            }
        }
   
    }
    // if loop is stoped clean up io_uring structures
    io_uring_queue_exit(&args->ring);

    #endif


    #ifdef ZERO_COPY

    fips_buf_thread_arg_t fips_buf_thread_arg = {0};
    fips_buf_thread_arg.process_arg = args->arg;
    printf("attach from batch_read_batch_write %d\n", fips_buf_attach(&fips_buf_thread_arg));

    // Used for the references to the corresponding array index.
    // Is used to assign submissions and completions in io_uring
    int array_idx[RING_SIZE];
    // Contains the buffer positions that are free and can be reused in places
    // that are greater than idx.
    int buffer_position[RING_SIZE];
    int idx = 0;
    // initialisation of the array_idx and buffer_position arrays
    for (int i = 0; i<RING_SIZE; i++){
        array_idx[i] = i;
        buffer_position[i] = i;
    }
    // Pointer contains position to element in array_idx as reference for the
    // submission element
    int *data;
    // actual position to the local buffer
    int buffer_idx = 0;

    struct iovec iovec_buf[RING_SIZE][BUF_SIZE];
    #ifdef BIN_TO_STRING
    int line_size = LINE_SIZE;
    char buffer_array[RING_SIZE][BUF_SIZE][line_size];
    struct iovec iovec_buf_str[RING_SIZE][BUF_SIZE];

    for (int i = 0; i<RING_SIZE; i++){
        for(int j = 0; j<BUF_SIZE;j++){
            iovec_buf_str[i][j].iov_base = &buffer_array[i][j][0];
            iovec_buf_str[i][j].iov_len = line_size;
        }
    }
    #endif
    uint64_t tags[RING_SIZE] = {0};

    // run until shutdown variable is set to true through SIGINT    
    while(!do_shutdown){
        // fill submission queue
        while(!do_shutdown){

            // If idx equals BUF_SIZE, the local buffer is completely filled 
            // and cannot hold any further elements. Completion queue elements 
            // must first be processed and memory must be released in the local buffer
            if(idx == (RING_SIZE)){
                break;
            }
            buffer_idx = buffer_position[idx];
            int ret = fips_buf_read(&fips_buf_thread_arg, iovec_buf[buffer_idx], BUF_SIZE, &tags[buffer_idx], 0);
        
            if (ret != FIPS_BUF_SUCCESS) {
                // fprintf(stderr, "fips_buf_read failed: %d segment %d \n", ret, fips_buf_thread_arg.assignment->start_segment);
                // fflush(stderr);
                // sched_yield();
                nanosleep(&sleeptime,NULL); 
                continue;
            }
            // printf("tag before: %lu\n", tags[buffer_idx]);

            // get free submission queue element
            // on error break first and try to consume element in second loop
            sqe = io_uring_get_sqe(&args->ring);
            if(sqe == NULL){
                fprintf(stderr, "submission queue full");
                break;
            }
            
            #ifndef BIN_TO_STRING
            for(int j=0;j<BUF_SIZE;j++){
                iovec_buf[buffer_idx][j].iov_len = strlen(iovec_buf[buffer_idx][j].iov_base); // TODO: read number of elements directly from shared memory
                }
            io_uring_prep_writev(sqe, args->file_id, iovec_buf[buffer_idx], BUF_SIZE, -1);
            #else
            thread_local static char string_timestamp[26];
            thread_local static time_t chached_timestamp;
            for ( int i =0; i< BUF_SIZE; i++){
              fips_bin_message_t* message = iovec_buf[buffer_idx][i].iov_base;
              memset(iovec_buf_str[buffer_idx][i].iov_base,0, line_size);
              if (message->timestamp != chached_timestamp){
                chached_timestamp = message->timestamp;
                ctime_r(&chached_timestamp, string_timestamp);
              }
              strncpy(iovec_buf_str[buffer_idx][i].iov_base, string_timestamp, 26);
              ((char*)iovec_buf_str[buffer_idx][i].iov_base)[24] = ':';
              inet_ntop(AF_INET, &message->address4, ((char*)iovec_buf_str[buffer_idx][i].iov_base)+25, line_size);
              strncat(iovec_buf_str[buffer_idx][i].iov_base, " ",line_size-16);
              strncat(iovec_buf_str[buffer_idx][i].iov_base, &message->data,line_size-17);
              iovec_buf_str[buffer_idx][i].iov_len = strlen(iovec_buf_str[buffer_idx][i].iov_base);
              ((char*)iovec_buf_str[buffer_idx][i].iov_base)[iovec_buf_str[buffer_idx][i].iov_len] = '\n';
              iovec_buf_str[buffer_idx][i].iov_len++;
            }
            io_uring_prep_writev(sqe, args->file_id, iovec_buf_str[buffer_idx], BUF_SIZE, -1);
            #endif
            // save the current position in the sqe element so that it can be reassigned after completion
            io_uring_sqe_set_data(sqe, &array_idx[buffer_idx]);
            
            ++idx;
            
        }

        // if io_uring is filled, submission takes place
        io_uring_submit(&args->ring);
        
        // consumption loop of completion queue
        while(!do_shutdown){
            // checks if a completion event is available (doesnt wait like
            // io_uring_wait function) if not break loop and try to write new log
            // messages to the submission queue
            int status = io_uring_peek_cqe(&args->ring, &cqe);
            if (status == -EAGAIN) {
              break;
            }

            --idx;
            // save buffer position of completed event
            data = io_uring_cqe_get_data(cqe);
            buffer_position[idx] = *data;
            
            // if completion event is available, mark as seeen to free the place
            io_uring_cqe_seen(&args->ring, cqe);
            // printf("tag after: %lu\n", tags[*data]);
            int ret = fips_buf_return(&fips_buf_thread_arg, tags[*data]);
            if (ret != FIPS_BUF_SUCCESS) {
                fprintf(stderr, "fips_buf_return failed: %d\n", ret);
            }

            
            if(idx == 0){
                break;
            }
        }
   
    }
    // if loop is stoped clean up io_uring structures
    io_uring_queue_exit(&args->ring);
    printf("detach %d\n", fips_buf_detach(&fips_buf_thread_arg));
    #endif
   
}

void *reader_thread(void *data) {

    int read_init;
    
    struct io_uring_sqe *sqe = NULL;
    struct io_uring_cqe *cqe = NULL;


    struct thread_args *thread_data = (struct thread_args*) data;


    switch(thread_data->cmd_args->io_uring_mode){

        case SINGLE_READ_SINGLE_WRITE:
        {
            fprintf(stdout, "start single_read_single_write routine\n");
            single_read_single_write(thread_data, sqe, cqe, thread_data->cmd_args);
            break;
        }
        case SINGLE_READ_BATCH_WRITE:
        {
            fprintf(stdout, "start single_read_batch_write routine\n");
            single_read_batch_write(thread_data, sqe, cqe);
            break;
        }
        case BATCH_READ_SINGLE_WRITE:
        {
            fprintf(stdout, "start batch_read_single_write routine\n");
            batch_read_single_write(thread_data, sqe, cqe);
            break;
        }
        case BATCH_READ_BATCH_WRITE: 
        {
            fprintf(stdout, "start batch_read_batch_write routine\n");
            batch_read_batch_write(thread_data, sqe, cqe);
            break;
        }
        default:
            printf("Select io_uring mode");
    }

    return NULL;
}





int main(int argc, char *args[]){    

    set_signal_handler();
    #ifndef ZERO_COPY
    int read_init, seg_count, thread_count;
    struct arguments arguments;


    struct shmrbuf_reader_arg_t *reader_struct;
    if((reader_struct = (struct shmrbuf_reader_arg_t *) calloc(1, sizeof(struct shmrbuf_reader_arg_t))) == NULL){
        perror("calloc of reader struct failed");
        exit(EXIT_FAILURE);
    };

    reader_struct->shm_key = "./udpsvr.log";

    if ((read_init = shmrbuf_init((union shmrbuf_arg_t *)reader_struct,
                                  SHMRBUF_READER)) != IO_IPC_SUCCESS) {
      fprintf(stdout, "reader status: %d\n", read_init);
      if (read_init != 0) {
        fprintf(stderr, "initalization of reader failed %d\n", read_init);
        free(reader_struct);
        exit(EXIT_FAILURE);
      }
    }

    arguments.path = "/mnt/scratch/signer/bind_logs/read.txt";
    arguments.thread_number = reader_struct->global_hdr->segment_count;
    // arguments.io_uring_mode = BATCH_READ_SINGLE_WRITE;
    arguments.reader_struct = reader_struct;

    int argp_return = argp_parse(&argp, argc, args, 0, 0, &arguments);
    printf("number of threads: %d\n", arguments.thread_number);

    
    printf("io_uring_mode: %d\n", arguments.io_uring_mode);
    struct thread_args thread_data[arguments.thread_number];

    // Determine the number of shared memory segments per io uring
	seg_count = reader_struct->global_hdr->segment_count / arguments.thread_number;
	int remainder = reader_struct->global_hdr->segment_count % arguments.thread_number;
	int segments_per_thread[arguments.thread_number + 1];
	segments_per_thread[0] = 0;
	for(int i = 0; i < arguments.thread_number; ++i){
    	segments_per_thread[i+1] = (i < remainder) ? (seg_count + 1) : seg_count;
	}

    int file_id[1];
    file_id[0] = open(arguments.path, O_WRONLY | O_CREAT | O_APPEND, 0666);
        if(file_id < 0){
            perror("open");
        }
    
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    io_uring_queue_init_params(RING_SIZE, &thread_data[0].ring, &params);
    int ret = io_uring_register_files(&thread_data[0].ring, file_id, 1);
    if(ret){
        fprintf(stderr, "Error on registering buffers\n");
    }

    for(int i = 0; i < arguments.thread_number; i++){
        if(i){
            params.wq_fd = thread_data[0].ring.ring_fd;
            params.flags |= IORING_SETUP_ATTACH_WQ;
            io_uring_queue_init_params(RING_SIZE, &thread_data[i].ring, &params);
            ret = io_uring_register_files(&thread_data[i].ring, file_id, 1);
            if(ret){
                fprintf(stderr, "Error on registering buffers\n");
            }
        }
        thread_data[i].thread_id = i;
        thread_data[i].file_id = file_id[0];
        thread_data[i].reader_struct = reader_struct;
        thread_data[i].cmd_args = &arguments;
        thread_data[i].segment_range = segments_per_thread;
    }


    // for(int i = 0; i < arguments.thread_number; i++){
    //     io_uring_queue_init(BUF_SIZE, &thread_data[i].ring,0);
    //     thread_data[i].thread_id = i;
    //     thread_data[i].reader_struct = reader_struct;
    //     thread_data[i].file_id = file_id[0];
    //     thread_data[i].cmd_args = &arguments;
    //     // TODO: add file registering for non polling mode
    //     // TODO: experiment with IORING_SETUP_ATTACH_WQ (see https://github.com/axboe/liburing/issues/571#issuecomment-1106480309)
    // }

    // else {
    //     struct io_uring_params params;
    //     memset(&params, 0, sizeof(params));
    //     // flag to activate polling mode
    //     params.flags |= IORING_SETUP_SQPOLL;
    //     params.sq_thread_idle = 2000;

        // io_uring_queue_init_params(BUF_SIZE, &thread_data[0].ring, &params);
        // int ret = io_uring_register_files(&thread_data[0].ring, file_id, 1);
        // if(ret){
        //     fprintf(stderr, "Error on registering buffers\n");
        // }

        // for(int i = 0; i < arguments.thread_number; i++){
        //     if(i){
        //         params.wq_fd = thread_data[0].ring.ring_fd;
        //         params.flags |= IORING_SETUP_ATTACH_WQ;
        //         io_uring_queue_init_params(BUF_SIZE, &thread_data[i].ring, &params);
        //         ret = io_uring_register_files(&thread_data[i].ring, file_id, 1);
        //         if(ret){
        //             fprintf(stderr, "Error on registering buffers\n");
        //         }
        //     }
        //     thread_data[i].thread_id = i;
        //     thread_data[i].file_id = file_id[0];
        //     thread_data[i].reader_struct = reader_struct;
        //     thread_data[i].cmd_args = &arguments;
    // }
    // }

    

    pthread_t threads[arguments.thread_number];
    for (int i = 0; i < arguments.thread_number; i++){
        if (pthread_create(&threads[i], NULL, reader_thread, (void *) &thread_data[i])){
            perror("Error on creating threads");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < arguments.thread_number; i++){
        pthread_join(threads[i], NULL);
    }
    // TODO: close file descriptor
    int retval = shmrbuf_finalize((union shmrbuf_arg_t*) thread_data->reader_struct, SHMRBUF_READER);
    if(retval == IO_IPC_SUCCESS){
        fprintf(stderr, "Reader succesful detached from shared memory\n");
    }else {
        fprintf(stderr, "Error on detaching shared memory: %d\n", retval);
    };

    #endif


    #ifdef ZERO_COPY

    fips_buf_arg_t arg = {0};
    struct arguments arguments;
    arguments.thread_number = 1;
    arguments.path = "/mnt/scratch/signer/bind_logs/read.txt";
    int argp_return = argp_parse(&argp, argc, args, 0, 0, &arguments);

    arguments.thread_number = 1;
    struct thread_args thread_args[arguments.thread_number];
    pthread_t threads[arguments.thread_number];

    arg.role = FIPS_READER;
    // arg.shm_name = "/fips_zero_copy";
    // arg.line_size = LINE_SIZE;
    // arg.max_sqe_count = 1024;
    // arg.line_count_exp = 22;
    // arg.max_reader_count = 2;
    // arg.max_reader_thread_count = 17;
    // arg.max_segment_count = 17;
    // arg.flags = FIPS_BUF_FLAG_OVERWRITE;

    char *config_file = getenv("FIPS_BUF_CONF");
    int fips_init_return = 0;
    if (config_file)
      fips_init_return = fips_buf_init(&arg, config_file);
    else
      fips_init_return = fips_buf_init(&arg, "/etc/fips_buf.conf");
    if(fips_init_return != 0){
        printf("error on fips buf init method: %d\n", fips_init_return);
        exit(EXIT_FAILURE);

    } else{
        printf("fips buf initialization succesful: %d\n", fips_init_return);
    }
    
    int file_id[1];
    file_id[0] = open(arguments.path, O_WRONLY | O_CREAT | O_APPEND, 0666);
        if(file_id[0] < 0){
            perror("open");
        }
    
    unsigned int num[2] = {1,1};
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    io_uring_queue_init_params(RING_SIZE, &thread_args[0].ring, &params);
    io_uring_register_iowq_max_workers(&thread_args[0].ring, num);
    int ret = io_uring_register_files(&thread_args[0].ring, file_id, 1);
    if(ret){
        fprintf(stderr, "Error on registering buffers\n");
    }
    for(int i = 0; i < arguments.thread_number; i++){
        if(i){
            params.wq_fd = thread_args[0].ring.ring_fd;
            params.flags |= IORING_SETUP_ATTACH_WQ;
            io_uring_queue_init_params(RING_SIZE, &thread_args[i].ring, &params);
            ret = io_uring_register_files(&thread_args[i].ring, file_id, 1);
            if(ret){
                fprintf(stderr, "Error on registering buffers\n");
                
            }
        }
        
        thread_args[i].arg = &arg;
        thread_args[i].file_id = file_id[0];
        thread_args[i].cmd_args = &arguments;
    }
    
    for (int i = 0; i < arguments.thread_number; i++){
        if (pthread_create(&threads[i], NULL, reader_thread, (void *) &thread_args[i])){
            perror("Error on creating threads");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < arguments.thread_number; i++){
        pthread_join(threads[i], NULL);
    }
    
    printf("destroy %d\n", fips_buf_destroy(&arg, 0));

    pthread_exit(NULL);



    #endif

}


