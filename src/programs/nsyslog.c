#include <shm_ringbuf.h>
#include <stdio.h>


#define SHM_NLINES 100000
#define MY_OWN_MESSAGE "Shared Memory Nachricht für Testzwecke.\n" 
#define MESSAGE_SIZE (sizeof(MY_OWN_MESSAGE) - 1)

void syslog(){
    int retval;
    struct shmrbuf_writer_arg_t * shmrbuf_arg;

    if((shmrbuf_arg = (struct shmrbuf_writer_arg_t *) calloc(sizeof(struct shmrbuf_writer_arg_t),1)) == NULL)
        {
            perror("calloc failed");
            exit(EXIT_FAILURE);
        }

    shmrbuf_arg->line_count = SHM_NLINES;
    shmrbuf_arg->line_size = MESSAGE_SIZE;
    shmrbuf_arg->shm_key = "test";
    shmrbuf_arg->segment_count = 1;
    shmrbuf_arg->reader_count = 1;
    shmrbuf_arg->flags = SHMRBUF_FRCAT;

    if((retval = shmrbuf_init((union shmrbuf_arg_t *)shmrbuf_arg, SHMRBUF_WRITER)) != IO_IPC_SUCCESS)
        {
            if(retval > 0)
            {
                perror("shm_rbuf_init failed");
            }
            else 
            {
                fprintf(stderr,"shm_rbuf_init failed : error code %d\n",retval);
            }
            free(shmrbuf_arg);
            exit(EXIT_FAILURE);
        }

}


int main(){
    printf("Test");
}
