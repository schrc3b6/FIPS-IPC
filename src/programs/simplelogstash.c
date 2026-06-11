#include  <stdio.h>
#include <liburing.h>
#include <time.h>
#include <argp.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <time.h>

// Local includes
#include <shm_ringbuf.h>
#include <io_ipc.h>

#define DEFAULT_LOG "simplelogstash.log"
#define OPEN_FLAGS O_WRONLY | O_CREAT | O_TRUNC | O_APPEND
#define OPEN_PERM 0644

#define QUEUE_SIZE 100
#define LINEBUF_SIZE 128

// Helpers
#define UNUSED(x)(void)(x)

// Global variables
static char * logfile = DEFAULT_LOG;
static char * shmkey = "udpsvr.log";

static uint64_t rcv_count = 0;
static uint64_t write_count = 0;
static sig_atomic_t running = true;
struct timespec timeout = {.tv_sec=1,.tv_nsec=0};

struct io_buf_t
{
    struct iovec iovs[QUEUE_SIZE];
    char logmsgbuf[QUEUE_SIZE][LINEBUF_SIZE];
};

static struct argp_option options[] = 
{
    {"file", 'f', "FILEPATH", 0, "Specify the logfile",0},
    {0}
};

// Argparse

static error_t parse_opt(int key, char *arg, struct argp_state *state) 
{

    switch (key) {
        case 'f':
            logfile = arg;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num == 0) 
            {
                shmkey = arg;
            } 
            else 
            {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if (shmkey == NULL) 
            {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "SHM_KEY",
    .doc = "Simple program for writing log messages from a shared memory ringbuffer to a file"
};

void sig_handler(int signal)
{
    UNUSED(signal);
    running = false;
}

int8_t block_signals(void)
{
    sigset_t set;
    if(sigfillset(&set))
	{
        return -1;
    }

    if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM))
	{
        return -1;
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL))
	{
        return -1;
    }

    return 0;
}

int write_routine(void){

    int logfile_fd, retval, i;
    bool second_buf = false, error = false;
    int read_index;
    struct io_uring ring;
    struct io_uring_sqe * sqe = NULL;
    struct io_uring_cqe * cqe = NULL;
    struct io_buf_t * io_buf1;
    struct io_buf_t * io_buf2;
    struct shmrbuf_reader_arg_t rbuf_arg = {.shm_key = shmkey};

    if((io_buf1 = calloc(sizeof(struct io_buf_t), 1)) == NULL || (io_buf2 = calloc(sizeof(struct io_buf_t), 1)) == NULL)
    {
        perror("calloc failed");
        return -1;
    }

    for(i = 0; i < QUEUE_SIZE; i++)
    {
        io_buf1->iovs[i].iov_base = io_buf1->logmsgbuf[i];
        io_buf1->iovs[i].iov_len = LINEBUF_SIZE;
        io_buf2->iovs[i].iov_base = io_buf2->logmsgbuf[i];
        io_buf2->iovs[i].iov_len = LINEBUF_SIZE;
    }

    if((logfile_fd = open(logfile, OPEN_FLAGS, OPEN_PERM)) == -1)
    {
        perror("open failed");
        free(io_buf1);
        free(io_buf2);
        return -1;
    }

    if(io_uring_queue_init(QUEUE_SIZE, &ring, 0) == -1)
    {
        perror("ip_uring_queue_init failed");
        close(logfile_fd);
        free(io_buf1);
        free(io_buf2);
        return -1;
    }

    if((retval = shmrbuf_init((union shmrbuf_arg_t *)&rbuf_arg, SHMRBUF_READER)) != IO_IPC_SUCCESS)
    {
        if(retval > 0) {perror("shmrbuf_init failed");}
        else { fprintf(stderr, "shmrbuf_init failed with error code %d\n", retval);}
        io_uring_queue_exit(&ring);
        close(logfile_fd);
        free(io_buf1);
        free(io_buf2);
        return -1;
    }

    uint8_t segment_count = rbuf_arg.global_hdr->segment_count;

    while (running)
    {
        
        read_index = 0;

       if(second_buf)
       {
            if((read_index = shmrbuf_readv_rng(&rbuf_arg, io_buf2->iovs, QUEUE_SIZE, LINEBUF_SIZE, 0, segment_count, NULL)) < 0)
            {
                fprintf(stderr, "Error in shmrbuf_readv_rng : error code %d\n", read_index);
                error = true;
                break;
            }
       }

       else 

       {
            if((read_index = shmrbuf_readv_rng(&rbuf_arg, io_buf1->iovs, QUEUE_SIZE, LINEBUF_SIZE, 0, segment_count, NULL)) < 0)
            {
                fprintf(stderr, "Error in shmrbuf_readv_rng : error code %d\n", read_index);
                error = true;
                break;
            }
       }

        if(sqe != NULL)
        {
            if(io_uring_wait_cqe(&ring, &cqe) == -1 || cqe->res < 0)
            {
                perror("io_uring_wait_cqe failed");
                io_uring_queue_exit(&ring);
                error = true;
                break;
            }

            io_uring_cqe_seen(&ring, cqe);   
            sqe = NULL;         

        }

        if(read_index > 0)
        {
            rcv_count += read_index;

            if((sqe = io_uring_get_sqe(&ring)) == NULL){
                perror("io_uring_get_sqe failed");
                error = true;
                break;
            }

            else 
            {
                if(second_buf)
                {
                    io_uring_prep_writev(sqe, logfile_fd, io_buf2->iovs, read_index, -1);
                }   
                else 
                {
                    io_uring_prep_writev(sqe, logfile_fd, io_buf1->iovs, read_index, -1);
                }

                if(io_uring_submit(&ring) == -1)
                {
                    perror("io_uring_submit failed");
                    error = true;
                    break;
                }
                else 
                {
                    write_count += read_index;
                    second_buf = !second_buf;
                }
            
            }

        }

        else 
        {
            nanosleep(&timeout, NULL);
        }

    }

    io_uring_queue_exit(&ring);

    if((retval = shmrbuf_finalize((union shmrbuf_arg_t *)&rbuf_arg, SHMRBUF_READER)) != IO_IPC_SUCCESS)
    {
        fprintf(stderr,"shmrbuf_finalize failed with error code %d\n", retval);
        error = true;
    }

    if(close(logfile_fd) == -1)
    {
        perror("close failed");
        error = true;
    }

    free(io_buf1);
    free(io_buf2);
    
    return (error) ? -1 : 0;
}

int main(int argc, char **argv) {

    if(argp_parse(&argp, argc, argv, 0, 0, NULL) == ARGP_ERR_UNKNOWN)
    {
        exit(EXIT_FAILURE);
    }

    if(block_signals() == -1)
    {
        fprintf(stderr, "block signals failed\n");
    }

    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR)
	{
        perror("Failed to set signal handler");
    }


    if(write_routine() == -1)
    {
        fprintf(stderr, "write_routine failed\n");
        exit(EXIT_FAILURE);
    }

    printf("\nTotal messages read : %ld, total messages written : %ld\n", rcv_count, write_count);
    exit(EXIT_SUCCESS);    
}
