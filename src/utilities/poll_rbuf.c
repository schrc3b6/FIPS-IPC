#define _GNU_SOURCE
#include <stdio.h>
#include <sys/shm.h>
#include <shm_ringbuf.h>
#include <time.h>
#include <argp.h>
#include <math.h>
#include <signal.h>

// config
#define DEFAULT_KEY "udpsvr.log"
#define DEFAULT_TIMEOUT 1

// helpers
#define MAX(a,b)((a > b) ? a : b)
#define MIN(a,b)((a > b) ? b : a)
#define UNUSED(x)(void)(x)

// return values
#define RETURN_FAIL -1
#define RETURN_SUCC 0

// global variables
static char * shm_key = DEFAULT_KEY;
static bool header = false;
static bool segments = false;
static bool repeat = false;
static sig_atomic_t running = true;
static struct timespec timeout = {.tv_nsec=0, .tv_sec=DEFAULT_TIMEOUT};

const char *argp_program_version = "poll_rbuf 0.0";
static char args_doc[] = "SHM_KEY";

static const char argp_program_doc[] = 
"poll_rbuf.\n"
"\n"
"Utility for viewing status information of a shmrbuf.h ringbuffer";

static const struct argp_option options[] = {
	{ "repeat", 'r', "TIMEOUT", OPTION_ARG_OPTIONAL, "Print repeatedly with timeout [HUNDREDTHS]", 0},
	{ "info", 'i', NULL, 0, "Display full information", 0},
	{ "header", 'h', NULL, 0, "Display header information", 0},
	{ "segments", 's', NULL, 0, "Display segment information", 0},
    {0}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state);

static const struct argp argp = {
	.options = options,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = argp_program_doc
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	unsigned int hundredths;

	switch (key) {
		case 'r':
			repeat = true;

			if(arg)
			{
				hundredths = MIN(1000, MAX((int)(strtol(arg,NULL,10)), 1));
				timeout.tv_sec = (int)(hundredths / 100);
				timeout.tv_nsec = (hundredths % 100) * 10000000;
			}
			break;

		case 's':
			segments = true;
			break;

		case 'h':
			header = true;
			break;

		case 'i':
			header = true;
			segments = true;
			break;

		case ARGP_KEY_ARG:

			if(state->arg_num == 0)
			{
				shm_key = arg;
			}
			else 
			{
				argp_usage(state);
				return ARGP_ERR_UNKNOWN;
			}
			break;

		case ARGP_KEY_END:
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int8_t block_signals(void)
{
    sigset_t set;

    if(sigfillset(&set))
    {
        return RETURN_FAIL;
    }

   	if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM))
    {
        return RETURN_FAIL;
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL))
    {
        return RETURN_FAIL;
    }

    return RETURN_SUCC;
}

void sig_handler(int signal)
{
    UNUSED(signal);
    running = false;
}

void print_rbuf_info(struct shmrbuf_reader_arg_t * rbuf_arg)
{
	struct shmrbuf_global_hdr_t * global_hdr = rbuf_arg->global_hdr;

	printf("\n#######################################\n");
	printf("Ringbuffer at %p\n\n",(void *)global_hdr);
	printf("Checksum : %d\n", global_hdr->checksum);
	printf("Number of segments: %d\n",global_hdr->segment_count);
	printf("Number of lines per segment: %u\n",global_hdr->line_count);
	printf("Line size: %u Bytes\n",global_hdr->line_size);
	printf("Total buffer size: %u Bytes\n",global_hdr->line_count * global_hdr->line_size * global_hdr->segment_count);
	printf("Overwrite: %s\n",(global_hdr->overwrite) ? "true" : "false");
	printf("Number of readers: %d\n",global_hdr->reader_count);
	printf("Writer attached: %s\n", (global_hdr->writer_att) ? "true" : "false");

	for(int i = 0; i < global_hdr->reader_count; i++)
	{
		printf("Reader %d attached: %s\n", i, (*(&global_hdr->first_reader_att + i)) ? "true" : "false");
	}
	
}

void print_rbuf_overview(struct shmrbuf_reader_arg_t * rbuf_arg)
{

	struct shmrbuf_global_hdr_t * global_hdr = rbuf_arg->global_hdr;

	struct shmrbuf_seg_rhdr_t * hdr;
	uint64_t total_free = 0, total_used = 0;
	for(int i = 0; i < global_hdr->segment_count; i++){
		hdr = &rbuf_arg->segment_hdrs[i];

		atomic_uint_fast32_t * reader;
		uint64_t mdist = 0, dst;

		if(segments)
		{
			printf("\n#######################################\n");
			printf("Segment %d at %p\n\n", i, (void*)hdr->write_index);
			printf("Writer at line %ld, address %p\n",*hdr->write_index, (char *)hdr->data + rbuf_arg->global_hdr->line_size * (*hdr->write_index));
		}

		for(int i = 0; i < rbuf_arg->global_hdr->reader_count; i++)
		{
			reader = hdr->write_index + (i + 1);
			dst = (*reader <= *hdr->write_index) ? (*hdr->write_index - *reader) : (rbuf_arg->global_hdr->line_count - (*reader - *hdr->write_index));
			mdist = (dst > mdist) ? dst : mdist;

			if(segments){printf("Reader %d at line %ld, address %p\n", i,  *reader, (char *)hdr->data + rbuf_arg->global_hdr->line_size * (*reader));}
		}

		total_free += rbuf_arg->global_hdr->line_count - mdist - 1;
		total_used += mdist + 1;

		if(segments)
		{
			printf("Lines total: %u\n", rbuf_arg->global_hdr->line_count);
			printf("Lines used: %lu\n", mdist + 1);
			printf("Lines free: %lu\n",rbuf_arg->global_hdr->line_count - mdist - 1);
			printf("Load percentage: %0.2f\n\n",((mdist + 1) /  (double) rbuf_arg->global_hdr->line_count) * 100);
		}

	}

	printf("\n#######################################\n");
	printf("Total\n\n");
	printf("Lines total: %u\n", rbuf_arg->global_hdr->line_count * rbuf_arg->global_hdr->segment_count);
	printf("Lines used: %lu\n", total_used);
	printf("Lines free: %lu\n",total_free);
	printf("Load percentage: %0.2f\n\n",((total_used) /  (double) (rbuf_arg->global_hdr->line_count * rbuf_arg->global_hdr->segment_count)) * 100);

}

int main(int argc, char ** argv){

	int retval;
	struct shmrbuf_reader_arg_t rbuf_arg = {.shm_key=DEFAULT_KEY, .flags = SHMRBUF_NOREG};

	if(argp_parse(&argp,argc,argv,0,NULL,NULL))
	{
		exit(EXIT_FAILURE);
	}

	if(block_signals() != RETURN_SUCC)
	{
		fprintf(stderr, "Failed to block signals\n");
	}

	if((retval = shmrbuf_init((union shmrbuf_arg_t *)&rbuf_arg, SHMRBUF_READER)))
	{
		if(retval > 0) {fprintf(stderr,"shm_rbuf_init failed : %s\n", strerror(retval));}
		else {fprintf(stderr,"shm_rbuf_init failed with error code %d\n",retval);}

		exit(EXIT_FAILURE);
	}

	if(header){print_rbuf_info(&rbuf_arg);}

	if(!repeat)
	{

		print_rbuf_overview(&rbuf_arg);

	} 
	else 
	{

		while (running)
		{
			print_rbuf_overview(&rbuf_arg);
			nanosleep(&timeout,NULL);
		}

	}

	if((retval = shmrbuf_finalize((union shmrbuf_arg_t *)&rbuf_arg, SHMRBUF_READER)))
	{
		fprintf(stderr,"shm_rbuf_init failed with error code %d\n",retval);
		exit(EXIT_FAILURE);
	}
	
}