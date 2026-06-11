#define _GNU_SOURCE 1
#include <argp.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <hs.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>

// Local includes
#include <ip_hashtable.h>
#include <ip_llist.h>
#include <io_ipc.h>
#include <ebpf_utils.h>
#include <uring_getline.h>
#include "ip_blacklist.skel.h"

// Default configuration
#define DEFAULT_BAN_TIME 60
#define DEFAULT_BAN_THRESHOLD 1
#define DEFAULT_THREAD_COUNT 4 // For multi-threading
#define DEFAULT_IPC_TYPE DISK
#define DEFAULT_IFACE "enp24s0f0np0"
#define DEFAULT_LOG "udpsvr.log"
#define DEFAULT_MATCH_REGEX "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} client (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+) exceeded request rate limit"
#define IP4_REGEX "((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)"
#define IP6_REGEX "([a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4})|([a-f0-9:]{0,35}::[a-f0-9:]{0,35})"
#define LINEBUF_SIZE 128
#define NTHREADS 1
#define QUEUE_SIZE 100 // Number of entries read at once

// Hyperscan
#define MATCH_REGEX_ID 0
#define IP4_REGEX_ID 1
#define IP6_REGEX_ID 2

// Return values
#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)

// Open options
#define OPEN_MODE O_RDONLY
#define OPEN_PERM 0644

// global variables
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ip_hashtable_t * htable;
static struct ip_llist_t * banned_list; 
static hs_database_t * database;
static enum ipc_type_t ipc_type = DEFAULT_IPC_TYPE;
static uint8_t thread_count = NTHREADS;
static uint16_t bantime = DEFAULT_BAN_TIME;
static uint16_t limit = DEFAULT_BAN_THRESHOLD;
static bool matching = false, verbose = false;
static bool wload_stealing = false;
static char * shm_key = DEFAULT_LOG;
static char * logfile = DEFAULT_LOG;
static char * regex = DEFAULT_MATCH_REGEX;
static char * interface = DEFAULT_IFACE;
static int ipv4_ebpf_map;
static int ipv6_ebpf_map;

// Timeout value for unbanning thread
#define NANOSECONDS_PER_MILLISECOND 1000000
#define TIMEOUT 200 * NANOSECONDS_PER_MILLISECOND

// Helpers
#define UNUSED(x)((void)x)

// Structs

// Parameters for unbanning thread
struct unban_targs_t{
	uint32_t wakeup_interval;
	uint64_t unban_count;
	int retval;
};

// Binary ip address representation
union ip_addr_t
{
	uint32_t ipv4;
	__uint128_t ipv6;
};

struct hs_context_t
{
	int domain;
	bool match;
	char * logstr;
	union ip_addr_t ip_addr;
};

// Parameters for banning threads
struct ban_targs_t {
	void * ipc_args;
	uint8_t thread_id;
	uint32_t wakeup_interval;
	uint64_t rcv_count;
	uint64_t ban_count;
	uint64_t steal_count;
	char strerror_buf[64];
	int retval;
};


// Argparse
const char *argp_program_version = "Simplefail2ban 1.0";
static const char argp_program_doc[] =
"Simplefail2ban.\n"
"\n"
"A minimal eBPF based IPS for testing purposes";

static char args_doc[] = "INTERFACE";

static const struct argp_option opts[] = {

	{ "file", 'f', "FILE", OPTION_ARG_OPTIONAL, "Set logifle as the chosen ipc type (optional: specify path to logfile)", 0},
	{"shm", 's', "KEY", OPTION_ARG_OPTIONAL, "Set shared memory as the ipc type (optional: specify file for shared memory key)", 0},
	{"threads", 't', "N", OPTION_ARG_OPTIONAL, "Enable multi-threading (optional: set number of banning threads to use)",0},
	{ "limit", 'l', "N", 0, "Set number of matches before a client is banned", 0},
	{ "bantime", 'b', "N", 0, "Set number of seconds a client should be banned", 0},
	{ "match", 'm', "REGEX", OPTION_ARG_OPTIONAL, "Use regex matching on logstrings (optional: specify match regex to use)", 0},
	{ "steal", 'w', NULL, 0, "Enable workload stealing for shared memory", 0},
	{ "verbose", 'v', NULL, 0, "Enable debug output", 0},
	{0},
};

// Struct passed to arg_parse
struct arguments
{
  bool ipc_set;
};

// Arguments parser for argparse
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	
	case 'f':

		if(arguments->ipc_set)
		{
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = DISK;

		if(arg != NULL)
		{
			logfile = arg;
		}

		break;

	case 's':

		if(arguments->ipc_set)
		{
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = SHM;

		if(arg)
		{
			shm_key = arg;
		}

		else 
		{
			shm_key = DEFAULT_LOG;
		}
		

		break;

	case 't':
            if(arg)
			{
				thread_count = (uint8_t) strtol(arg,NULL,10);
            
				if(get_nprocs() < thread_count)
				{
					thread_count = get_nprocs();
					fprintf(stderr,"Using maximum number of banning threads = %d\n",thread_count);
				}

				if(thread_count == 0)
				{
					thread_count = 1;
					fprintf(stderr,"Minimum 1 banning thread required\n");
				}
			}

			else 
			{
				thread_count = DEFAULT_THREAD_COUNT;
			}
            

            break;

	case 'l':
            
            limit = (uint16_t) strtol(arg,NULL,10);

			if(limit == 0)
			{
				fprintf(stderr,"Ban limit has to be at least 1\n");
				limit = 1;
			}			

            break;

	case 'b':
            
            bantime = (uint16_t) strtol(arg,NULL,10);

            break;

	case 'r':

			matching = true;

			if(arg != NULL)
			{
				regex = arg;
			}

            break;

	case 'm':

			matching = true;
			break;

	case 'w':

			wload_stealing = true;
			break;

	case 'v':

			verbose = true;
			break;

	case ARGP_KEY_ARG:
      	if (state->arg_num >=2 )
		{
			fprintf(stderr, "Too many arguments. See usage\n");
			argp_usage (state);
	  	}
		
		interface = arg;

		break;
	case ARGP_KEY_END:
		if (state->arg_num < 1)
		{
			interface = DEFAULT_IFACE;
		}

		if(thread_count > 1 && ipc_type == DISK)
		{
			fprintf(stderr,"No multithreading available for FILE IPC\n");
			thread_count = 1;
		}

		if(wload_stealing && ipc_type != SHM)
		{
			wload_stealing = false;
		}

	 
      break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = argp_program_doc,
};

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char * fmt, pthread_mutex_t * lock, FILE * fp, va_list targs)
{
    pthread_mutex_lock(lock);
    vfprintf(fp, fmt, targs);
    pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char* fmt,...)
{
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stdout_lock,stdout,targs);
    va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char * fmt,...)
{
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stderr_lock,stderr,targs);
    va_end(targs);
}

void sig_handler(int signal)
{
    UNUSED(signal);
    server_running = false;
}

int8_t block_signals(bool keep)
{
    sigset_t set;
    if(sigfillset(&set))
	{
        return RETURN_FAIL;
    }

    if(keep)
	{
        if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM))
		{
            return RETURN_FAIL;
        }
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL))
	{
        return RETURN_FAIL;
    }

    return RETURN_SUCC;
}


void * unban_thread_routine(void * args)
{
	/**
	*	Description: This this function represents the routine executed
	*   by the unbanning thread. While the global parameter "server_running"
	*   is true, it periodically wakes up and iterates through the banned_list,
	*   to unban clients whos bantime has elapsed.
	*   
	*   Parameters:
	*   	void * args : Pointer to struct unban_targs_t with thread parameters
	*
	*   Returns:
	* 		void * : Pointer to int returncode of the function
	**/


	struct unban_targs_t * targs = (struct unban_targs_t *) args;
	time_t ts;
	struct timespec timeout = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	char strerror_buf[64];
	struct ip_listnode_t *iterator, * prev;
	int retval;
	bool idle;

	// Blocks (blockable) signals except SIGINT and SIGTERM
	if(block_signals(true))
	{
        error_msg("Failed to block signals\n");
    }
	
	// Registers sig_handler to handle SIGINT and SIGTERM (-> server_running = false)
    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR)
	{
        error_msg("Failed to set signal handler : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
    }

	// Event loop
	while (server_running)
	{

		idle = true;

		// Gets current timestap for bantime evaluation
		if((ts = time(NULL)) == -1)
		{
			error_msg("Failed to obtain timestamp : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		// Aquires lock for head of the banned_list
		if(pthread_mutex_lock(&banned_list->lock))
		{
			pthread_mutex_unlock(&banned_list->lock);
			error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		// Find first entry in the banned_list whos bantime has elapsed.
		iterator = banned_list->head;

		if(iterator != NULL)
		{
			if((ts - iterator->timestamp) > bantime)
			{
				banned_list->head = NULL;
				idle = false;
			}
			else 
			{
				prev = iterator;
				iterator = iterator->next;
			}

			if(pthread_mutex_unlock(&banned_list->lock))
			{
				error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
				targs->retval = EXIT_FAIL;
				return &targs->retval;
			}

			if(prev != NULL){

				while(iterator != NULL)
				{

					if((ts - iterator->timestamp) > bantime)
					{
						prev->next = NULL;
						idle = false;
						break;
					}
					prev = iterator;
					iterator = iterator->next;
				}

			}

			// Unban all clients with an elapsed bantime
			while(iterator != NULL)
			{
				switch (iterator->domain)
				{
				case AF_INET:
						
					retval = bpf_map_delete_elem(ipv4_ebpf_map, iterator->key);
					break;
					
				case AF_INET6:

					retval = bpf_map_delete_elem(ipv6_ebpf_map, iterator->key);
					break; 

				default:
					retval = -1;
					error_msg("Invalid domain in banned list %d\n", iterator->domain);
				}

				if(retval != 0)
				{
					error_msg("Error deleting entry from ebpf map : error code %d\n", retval);
				} 

				else 
				{
					targs->unban_count++;
				}

				prev = iterator;
				iterator = iterator->next;

				if((retval = ip_hashtable_remove(htable, prev->key, prev->domain)) < 0)
				{
					error_msg("Error removing key from hashtable : error code %d\n",retval);
				}
					
				if((retval = ip_llist_remove(&prev, NULL)) < 0)
				{
					error_msg("Error removing node from banned list : error code %d\n",retval);
				}	

			}
				
		}
		else 
		{
			if(pthread_mutex_unlock(&banned_list->lock))
			{
				error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
				targs->retval = EXIT_FAIL;
				return &targs->retval;
			}
		}

		// Timeout after checking banned_list
		if(idle) {nanosleep(&timeout,NULL);}
	}
	
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}
// Todo: Unittest for regex match
int regex_match_handler(unsigned int id, unsigned long long from, unsigned long long to,
                  unsigned int flags, void *ctx)
				  {

	/**
	 *  Description : Handler function that is called if hs_scan finds a match.
	 *  
	 *  Parameters : 
	 * 		unsigned int id : ID of the matched regular expression (see hs_compile)
	 * 		unsigned long long from : Start index of the match
	 * 		unsigned long long to : End index of the match
	 * 		unsigned int flags : Flags set for match
	 *      void *ctx : Context pointer, expects pointer to struct ban_targs_t
	 * 
	 *  Returns : 
	 * 		int : 0, if matching should continue, 1 else.  
	*/

	UNUSED(flags);

	struct hs_context_t * context = (struct hs_context_t *)ctx;

	switch (id)
	{
	case MATCH_REGEX_ID:
		context->match = true;
		return (context->domain != -1 ) ? 1 : 0;
	
	case IP4_REGEX_ID:

		from = to;

		// Adjust to and from if not at the end of the address (assumes withespace around address)

		while(to + 1 < LINEBUF_SIZE && context->logstr[to] != ' ') {to++;}

		while(from > 0 && context->logstr[from-1] != ' ') {from--;}

		context->logstr[to] = '\0';

		if (inet_pton(AF_INET,&context->logstr[from],&context->ip_addr.ipv4) == 1) 
		{
			context->domain = AF_INET;
			context->logstr[to] = ' ';
			return (context->match) ? 1 : 0;
		}
		context->domain = -1;
		context->logstr[to] = ' ';
		return 0;

	case IP6_REGEX_ID:

		from = to;

		// Adjust to and from if not at the end of the address (assumes withespace around address)

		while(to + 1 < LINEBUF_SIZE && context->logstr[to] != ' ') {to++;}

		while(from > 0 && context->logstr[from-1] != ' ') { from--; }

		context->logstr[to] = '\0';

		if (inet_pton(AF_INET6, &context->logstr[from],&context->ip_addr.ipv6) == 1) 
		{
			context->domain = AF_INET6;
			context->logstr[to+1] = ' ';
			return (context->match) ? 1 : 0;
		}
		context->domain = -1;
		context->logstr[to+1] = ' ';
		return 0;

	default:
		return 1;
	}

}


void * ban_thread_routine(void * args)
{
	/**
	*	Description: This this function represents the routine executed
	*   by the banning threads. While the global parameter "server_running"
	*   is true, the choosen ipc api is queried for incoming messages. Messages
	*   are then parsed, and identified clients are logged to htable. If the banning 
	*   threshold has been exeeded, the clients ip is added to banned_list and the
	*   corresponding ebpf map.
	*   
	*   Parameters:
	*   	void * args : Pointer to struct ban_targs_t with thread parameters
	*
	*   Returns:
	* 		void * : Pointer to int returncode of the function
	**/

	struct ban_targs_t * targs = (struct ban_targs_t *)args;
	struct shmrbuf_reader_arg_t * shm_arg = NULL;
	struct file_io_t * file_arg = NULL;
	hs_scratch_t * scratch = NULL; 
	struct hs_context_t context;
	struct timespec tspec = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	struct iovec iovecs[QUEUE_SIZE];
	char * logstr_buf;
	uint64_t rcv_count = 0, ban_count = 0, steal_count = 0;
	int retval, recv_retval = 0, i;
	uint8_t seg_count, upper_seg = 0, lower_seg = 0;
	uint16_t nsteal = 0;
	uint16_t * nsteal_buf = (wload_stealing) ? &nsteal : NULL;

	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];

	if(memset(&values, 0, sizeof(values)) == NULL)
	{
		error_msg("Memset error \n");
	}

	if((logstr_buf = (char*) calloc(QUEUE_SIZE, LINEBUF_SIZE)) == NULL)
	{
		error_msg("calloc failed : %s\n",strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
		targs->retval = EXIT_FAIL;
		return &targs->retval;
	}

	for(i = 0; i < QUEUE_SIZE; i++)
	{
		iovecs[i].iov_base = &logstr_buf[LINEBUF_SIZE * i];
		iovecs[i].iov_len = LINEBUF_SIZE;
	}

	// Communication setup dependant on ipc_type
	if(ipc_type == DISK)
	{
		file_arg = (struct file_io_t *) targs->ipc_args;
	}

	else if(ipc_type == SHM)
	{

		shm_arg = (struct shmrbuf_reader_arg_t *) targs->ipc_args;

		if(targs->thread_id >= shm_arg->global_hdr->segment_count)
		{
			targs->retval = RETURN_SUCC;
			return &targs->retval;
		}

		// Determine the ringbuffer segments for the thread, as well as the range for workload stealing.
		seg_count = shm_arg->global_hdr->segment_count / thread_count;

		if((retval = shm_arg->global_hdr->segment_count % thread_count) > 0)
		{
			if(retval > targs->thread_id)
			{
				seg_count = seg_count + 1;
				lower_seg = targs->thread_id * seg_count;
			}
			else 
			{
				lower_seg = targs->thread_id * (seg_count + 1);
			}
		}
		else 
		{
			lower_seg = targs->thread_id * seg_count;
		}

		upper_seg = lower_seg + seg_count;
	}

	if(block_signals(false))
	{
        error_msg("failed to block signals\n");
    }

	if(matching)
	{
		if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
		{
			error_msg("hyperscan scratch space allocation failed\n");
			free(logstr_buf);
			targs->retval = EXIT_FAIL;
			return &targs->retval;
    	}	
	}
    
	// Event loop
	while (server_running)
	{

		// Message receiving dependent on ipc_type
		switch (ipc_type)
		{
		case DISK:
				
			if((recv_retval = uring_getlines(file_arg, iovecs, QUEUE_SIZE, LINEBUF_SIZE)) > 0)
			{
				
				for(i = 0; i < recv_retval; i++)
				{
					((char *)iovecs[i].iov_base)[iovecs[i].iov_len -1] = '\0';
				}
			}
			else if(recv_retval < 0)
			{
				error_msg("uring_getlines failed with error code %d\n", recv_retval);
				free(logstr_buf);
				targs->rcv_count = rcv_count;
				targs->ban_count = ban_count;
				targs->steal_count = steal_count;
				targs->retval = EXIT_FAIL;
				return &targs->retval;	

			}

			break;

		case SHM:

			if((recv_retval = shmrbuf_readv_rng(shm_arg, iovecs, QUEUE_SIZE, LINEBUF_SIZE, lower_seg, upper_seg, nsteal_buf)) > 0)
			{
				
				if(wload_stealing && nsteal > 0)
				{
					steal_count += nsteal;
					nsteal = 0;
				}

				for(i = 0; i < recv_retval; i++)
				{
					uint16_t len = iovecs[i].iov_len;
					char * str = (char*) iovecs[i].iov_base;
					while(len-- > 0)
					{
						if(str[len] == '\n') 
						{
							str[len] = '\0';
							break;
						}
					}
					
				}

			}

			else if (recv_retval < 0)
			{
				error_msg("shmrbuf_readv_rng failed with error code %d\n", recv_retval);
				targs->rcv_count = rcv_count;
				targs->ban_count = ban_count;
				targs->steal_count = steal_count;
				free(logstr_buf);
				targs->retval = EXIT_FAIL;
				return &targs->retval;
			}

			break;

		default:
			break;
		}

		if(recv_retval){

			rcv_count += recv_retval;

			for(i = 0; i < recv_retval; i++)
			{

				char * logstr = (char *) iovecs[i].iov_base;

				// If matching enabled, matches log message against regex
				if(matching)
				{
					context.match = false;
					context.domain = -1;
					context.logstr = logstr;

					if((retval = hs_scan(database, logstr, LINEBUF_SIZE, 0, scratch, regex_match_handler, &context)) != HS_SUCCESS && retval != HS_SCAN_TERMINATED)
					{
						error_msg("Hyperscan error for logstring %s : error code %d\n", logstr, retval);
						continue;
					}
					else if(!context.match || context.domain == -1)
					{
						continue;
					}
				}

				// Try to convert log message to IP address
				else 
				{
					if (inet_pton(AF_INET, logstr, &context.ip_addr.ipv4) == 1) 
					{
						context.domain = AF_INET;
					} 
					else if (inet_pton(AF_INET6, logstr, &context.ip_addr.ipv6) == 1) 
					{
						context.domain = AF_INET6;
					} 
					else 
					{
						continue;
					}
				}
				
				
				// Query htable for the number of times an ip address has been logged
				switch (context.domain)
				{
				case AF_INET:
						
						retval = ip_hashtable_insert(htable, &context.ip_addr.ipv4, AF_INET);

						break;

				case AF_INET6:

					retval = ip_hashtable_insert(htable, &context.ip_addr.ipv6, AF_INET6);

					break;
				
				default:
					continue;
				}

				if(retval < 1)
				{
					error_msg("Error in htable query for logstring : %s : Error Code %d\n", logstr, retval);
					continue;
				}

				// Ban client if ban threshold has been reached
				if(retval == limit)
				{
					time_t ts = time(NULL);

					switch (context.domain)
					{
					case AF_INET:
						if((retval = ip_llist_push(banned_list, &context.ip_addr.ipv4, &ts, AF_INET)) < 0)
						{
							error_msg("Error pushing to banned list for logstring : %s : Error Code %d\n", logstr, retval);
								continue;
						}
						retval = bpf_map_update_elem(ipv4_ebpf_map, &context.ip_addr.ipv4, &values, BPF_NOEXIST);
						break;
						
					case AF_INET6:
						if((retval = ip_llist_push(banned_list, &context.ip_addr.ipv6, &ts, AF_INET6)) < 0)
						{
							error_msg("Error pushing to banned list for logstring : %s : Error Code %d\n",logstr, retval);
								continue;
						}
						retval = bpf_map_update_elem(ipv6_ebpf_map, &context.ip_addr.ipv6, &values, BPF_NOEXIST);
						break;

					default:
						continue;
					}

					if(retval != EXIT_OK)
					{
						error_msg("Error adding entry to ebpf map : Error code %d : logstring : %s\n", retval, logstr);

						// set the hashtable counter to limit -1, so client can be banned again 
						if((retval = ip_hashtable_set(htable, &context.ip_addr, context.domain, limit-1)) < 0)
						{
							error_msg("ip_hashtable set failed, Error code: %d, logstring: %s\n", retval);
						}

						continue;
					}

					ban_count++;
					
				} 
			}
		}

		// Timeout, if no messages were read
		else 
		{
			nanosleep(&tspec,NULL);
		}

	}
	if(matching){hs_free_scratch(scratch);}
	free(logstr_buf);
	targs->rcv_count = rcv_count;
	targs->ban_count = ban_count;
	targs->steal_count = steal_count;
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}

bool main_cleanup(struct ban_targs_t ** targs, pthread_t ** tids)
{
	/**
	 * Description : Cleans up memory and io channels for the main function
	 * 
	 * Parameters : 
	 * 		 struct ban_targs_t ** targs : Pointer to array of thread argument structs
	 * 	     pthread_t ** tids : Pointer to arry of thread ids
	 * 
	 * Returns : 
	 * 		bool : true, if an error occured, else false
	*/

	int retval;
	bool error = false;

	if(targs != NULL && *targs != NULL && (*targs)[0].ipc_args != NULL)
	{

		switch (ipc_type)
		{
		case DISK:

			io_uring_queue_exit(&((struct file_io_t *)(*targs)[0].ipc_args)->ring);
			
			if(close(((struct file_io_t *)(*targs)[0].ipc_args)->logfile_fd) < 0)
			{
				perror("close");
				error = true;
			}

			free((*targs)[0].ipc_args);

			break;

		case SHM:

			if((retval = shmrbuf_finalize((union shmrbuf_arg_t *)(*targs)[0].ipc_args, SHMRBUF_READER)) != IO_IPC_SUCCESS)
			{
				fprintf(stderr, "shmrbuf_finalize failed with error code: %d\n", retval);
				error = true;
			}

			free((*targs)[0].ipc_args);

			break;
		
		default:
			break;
		}

		free(*targs);
		free(*tids);	
		*targs = NULL;
		*tids = NULL;

	}

	if((retval = ebpf_cleanup(interface, true, verbose)) < 0)
	{
		fprintf(stderr,"ebpf cleanup failed : error code %d\n", retval);
		error = true;
	}

	if(banned_list != NULL)
	{
		if((retval = ip_llist_destroy(&banned_list)) != IP_LLIST_SUCCESS)
		{
			fprintf(stderr, "ip_llist_destroy failed with error code %d\n", retval);
			error = true;
		}
	}
	
	if(htable != NULL)
	{
		if((retval = ip_hashtable_destroy(&htable)) < 0)
		{
			fprintf(stderr, "ip_hashtable_destroy failed with error code %d\n", retval);
			error = true;
		}
	}

	if(database != NULL)
	{
		if((retval = hs_free_database(database)) != HS_SUCCESS)
		{
			fprintf(stderr, "hs_free_database failed with error code %d\n", retval);
			error = true;

		}
	}	

	return error;

}


int main(int argc, char **argv)
{
	/**
	 * Description : Main function of the program. Parses commandline arguments, sets up
	 * the ipc api, loads the ebpf program, spawns unbanning and banning threads.
	 * 
	 * 
	*/
	
	// Variables
    struct arguments args = {.ipc_set=false};
	struct ban_targs_t * thread_args = NULL;
	struct unban_targs_t unban_targs = {.unban_count = 0,.wakeup_interval=TIMEOUT};
	struct file_io_t * file_io_args = NULL;
	struct shmrbuf_reader_arg_t * rbuf_arg = NULL;
	hs_platform_info_t * platform_info;
	hs_compile_error_t * compile_error;
	pthread_t * thread_ids = NULL;
	int retval;
	uint8_t i;

	// Parse commandline arguments
	retval = argp_parse(&argp, argc, argv, 0, NULL, &args);

	if (retval == ARGP_ERR_UNKNOWN)
	{
		exit(EXIT_FAILURE);
	}

	// Setup regex matching, compile chosen regex.
	if (matching) 
	{
		const char * const regexes[] = {regex, IP4_REGEX, IP6_REGEX};
		const unsigned int flags[] = {HS_FLAG_SINGLEMATCH , HS_FLAG_SINGLEMATCH, HS_FLAG_SINGLEMATCH};
		const unsigned int ids[] = {0 , 1, 2};


		if((platform_info = (hs_platform_info_t *) calloc(sizeof(hs_platform_info_t), 1)) == NULL)
		{
			perror("calloc failed");
		}

		else if(hs_populate_platform(platform_info) != HS_SUCCESS)
		{
			fprintf(stderr, "hs_populate_platform failed\n");
			free(platform_info);
			platform_info = NULL;
		}

		if(hs_compile_multi(regexes, flags, ids, 3, HS_MODE_BLOCK, platform_info, &database, &compile_error) != HS_SUCCESS)
		{
			fprintf(stderr,"hyperscan compilation failed with error code %d, %s\n", compile_error->expression, compile_error->message);
			hs_free_compile_error(compile_error);
			exit(EXIT_FAILURE);
		}

		if(platform_info != NULL)
		{
			free(platform_info);
			platform_info = NULL;
		}
    } 

	// Load ebpf program onto chosen interface and setup maps
    if(ebpf_setup(interface, verbose))
	{
		fprintf(stderr,"ebpf setup failed\n");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	if((ipv4_ebpf_map = open_bpf_map(FILE_BLACKLIST_IPV4)) == RETURN_FAIL || (ipv6_ebpf_map = open_bpf_map(FILE_BLACKLIST_IPV6)) == RETURN_FAIL)
	{
		fprintf(stderr,"failed to open bpf map  : %s\n",strerror(errno));
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init memory for thread arguments
	if((thread_ids = (pthread_t *) calloc(sizeof(pthread_t),thread_count)) == NULL ||
	   (thread_args = (struct ban_targs_t *) calloc(sizeof(struct ban_targs_t),thread_count)) == NULL)
	{
		perror("calloc failed");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init hashtable for tracking of logged ip addresses
	if((retval = ip_hashtable_init(&htable)) < 0)
	{
		fprintf(stderr,"ip_hashtable_init failed with error code %d\n", retval);
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}
	
	// Init linked list for tracking of banned ip addresses
	if((retval = ip_llist_init(&banned_list)) < 0)
	{
		fprintf(stderr,"ip_llist_init failed with error code %d\n", retval);
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init ipc communication dependent on chosen ipc_type
	switch (ipc_type)
	{
	case DISK:

		if((file_io_args = (struct file_io_t *) calloc(sizeof(struct file_io_t), 1)) == NULL)
		{
			perror("calloc failed");
		}

		else if((file_io_args->logfile_fd = open(logfile, O_RDONLY, 0644)) == -1)
		{
			perror("open failed");
		}

		else if(io_uring_queue_init(2, &file_io_args->ring, 0) == -1)
		{
			perror("ic_uring_queue_init failed");
		}

		else 
		{
			thread_args[0].ipc_args = (void*) file_io_args;
			break;
		}

		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);

		break;
	
	case SHM:

		if((rbuf_arg = (struct shmrbuf_reader_arg_t *)calloc(sizeof(struct shmrbuf_reader_arg_t),1)) == NULL)
		{
			perror("calloc failed");
			main_cleanup(&thread_args, &thread_ids);
			exit(EXIT_FAILURE);
		}

		rbuf_arg->shm_key = shm_key;

		if((retval = shmrbuf_init((union shmrbuf_arg_t *)rbuf_arg, SHMRBUF_READER)) != IO_IPC_SUCCESS)
		{
			if(retval > 0)
			{
				perror("shm_rbuf_init failed");
			}
			else {
				fprintf(stderr,"shm_rbuf_init failed : error code %d\n",retval);
			}
			main_cleanup(&thread_args, &thread_ids);
			exit(EXIT_FAILURE);
		}

		for(i = 0; i < thread_count; i++)
		{
			thread_args[i].ipc_args = (void*) rbuf_arg;
		}

		break;

	default:
		break;
	}
	
	// Create unbanning thread
	if(pthread_create(&thread_ids[0],NULL,unban_thread_routine,&unban_targs))
	{
		perror("pthread create failed for unban thread");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	} 
	
	else 
	{
		// Create banning threads
		for(i = 0; i < thread_count; i++)
		{
			thread_args[i].ban_count = 0;
			thread_args[i].rcv_count = 0;
			thread_args[i].thread_id = i;
			thread_args[i].wakeup_interval = TIMEOUT;

			if(i > 0)
			{
				if(pthread_create(&thread_ids[i],NULL,ban_thread_routine,&thread_args[i]))
				{
					perror("pthread create failed");
				}
			}

		}

		// Start main event loop
		ban_thread_routine(&thread_args[0]);

		for(i = 0; i < thread_count; i++)
		{
			if(pthread_join(thread_ids[i], NULL))
			{
				perror("pthread join failed");
			}
		}

	}

	uint64_t total_rcv_count = 0, total_ban_count = 0, total_steal_count = 0;

	printf("\n");

	// Aggregate and print receive and ban / unban counters.
	for(i = 0; i < thread_count; i++)
	{
		if(thread_args[i].retval != RETURN_SUCC)
		{
			fprintf(stderr,"Banning thread %d returned with error code %d\n",i,thread_args[i].retval);
		}

		if(wload_stealing)
		{
			printf("Thread %d : messages received: %ld, messages stolen: %ld, clients banned: %ld\n",i,thread_args[i].rcv_count, thread_args[i].steal_count,thread_args[i].ban_count);
		}
		else 
		{
			printf("Thread %d : messages received: %ld, clients banned: %ld\n",i,thread_args[i].rcv_count, thread_args[i].ban_count);
		}

		
	
		total_rcv_count += thread_args[i].rcv_count;
		total_ban_count += thread_args[i].ban_count;
		total_steal_count += thread_args[i].steal_count;

	}

	if(unban_targs.retval != RETURN_SUCC)
	{
		fprintf(stderr,"Unban thread returned with error code %d\n",thread_args[i].retval);
	}

	if(wload_stealing)
	{
		printf("Total messages received: %ld, total messages stolen: %ld, total clients banned: %ld, total clients unbanned: %ld\n",total_rcv_count, total_steal_count, total_ban_count, unban_targs.unban_count);

	}
	else 
	{
		printf("Total messages received: %ld, total clients banned: %ld, total clients unbanned: %ld\n",total_rcv_count, total_ban_count, unban_targs.unban_count);
	}

	if(main_cleanup(&thread_args, &thread_ids))
	{
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);

}	
