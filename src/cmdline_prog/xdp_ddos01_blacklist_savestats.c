/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
    Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
static const char *__doc__=
 " XDP ddos01: command line tool";
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <bpf.h>
#include <sys/resource.h>
#include <getopt.h>
#include <time.h>

#include <arpa/inet.h>
 
/* libbpf.h defines bpf_* function helpers for syscalls,
 * indirectly via ./tools/lib/bpf/bpf.h */
#include "libbpf.h"

//#include "bpf_util.h"

#include "xdp_ddos01_blacklist_common.h"

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"onetime",	no_argument,		NULL, 'o' },
	{"repeat",		required_argument,	NULL, 'r' },
	{0, 0, NULL,  0 }
};
#define OUTFILE out
#define DDOS_FILTER_MAX 2
#define XDP_ACTION_MAX (XDP_PASS + 1)
#define XDP_ACTION_MAX_STRLEN 11
#define NUM_CPUS 16
FILE *out;
char outbuffer[255];
int outbufferlen;
int fdglob;
static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]	= "XDP_ABORTED",
	[XDP_DROP]	= "XDP_DROP",
	[XDP_PASS]	= "XDP_PASS",
};
static const char *xdp_proto_filter_names[DDOS_FILTER_MAX] = {
	[DDOS_FILTER_TCP]	= "TCP",
	[DDOS_FILTER_UDP]	= "UDP",
};

static const char *action2str(int action)
{
	if (action < XDP_ACTION_MAX)
		return xdp_action_names[action];
	return NULL;
}

struct record_cpu{
	__u64 counter[NUM_CPUS];
	__u64 timestamp;
};
struct stats_record_cpu{
	struct record_cpu xdp_action[XDP_ACTION_MAX];
};
static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
		exit(EXIT_FAIL_MAP_FILE);
	}
	return fd;
}

static void stats_print_cpu(struct stats_record_cpu *record, struct stats_record_cpu *prev)
{
int i,j;
	__u64 period  = 0;
	double period_ = 0;
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		struct record_cpu *r = &record->xdp_action[i];
		struct record_cpu *p = &prev->xdp_action[i];
		//__u64 packets = 0;
		double pps[NUM_CPUS] = {0};
		for(j = 0;j<NUM_CPUS;j++){
			if (p->timestamp) {
			//packets = r->counter[j];//; - p->counter;
				period  = r->timestamp - p->timestamp;
				//printf("PEriod: %lld ", period); 
				if (period > 0) {
					period_ = ((double) period / NANOSEC_PER_SEC);
					pps[j] = (r->counter[j] - p->counter[j]) / period_;
				}
			}
            outbufferlen=snprintf(outbuffer,254,"%f,", pps[j] );
						write(fdglob,outbuffer,outbufferlen);

		}
	}
	period_ = ((double) period / NANOSEC_PER_SEC);

	outbufferlen=snprintf(outbuffer,254,"%f\n",period_);
			write(fdglob,outbuffer,outbufferlen);

}
static void stats_collect_cpu(int fd, struct stats_record_cpu *rec)
{
	int i,j;
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		if ((bpf_map_lookup_elem(fd, &i, values)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X, setting -1\n", i);
			for(j=0;j<NUM_CPUS;j++){//nr_cpus;j++){
				rec->xdp_action[i].counter[j] =-1;
			}
		}
		rec->xdp_action[i].timestamp = gettime();
		for(j=0;j<NUM_CPUS;j++){
			rec->xdp_action[i].counter[j] = values[j];
		}
	}
}


static void stats_poll(int interval)
{
	struct stats_record_cpu record_cpu, prev_cpu;
	int fd;
	/* TODO: Howto handle reload and clearing of maps */
	//fd = open_bpf_map(file_verdict);


	memset(&record_cpu, 0, sizeof(record_cpu));
	/* Trick to pretty printf with thousands separators use %' */

	while (1) {
 
		memcpy(&prev_cpu, &record_cpu, sizeof(record_cpu));
		fd = open_bpf_map(file_verdict);
		//stats_print_headers_cpu();
		stats_collect_cpu(fd,&record_cpu);
		stats_print_cpu(&record_cpu,&prev_cpu);
		close(fd);
        struct timespec req = {0,1000000};
        nanosleep(&req,NULL);
	}
	/* Not reached, but (hint) remember to close fd in other code */
	//close(fd);
}





int main (int argc, char **argv)
{
	int fd_blacklist;
	#ifdef DEBUG
	int fd_blacklist_debug;
	#endif
    int repeat = 0;
	int fd_verdict;
	int longindex = 0;
	int opt;
	int dport = 0;
	int proto = IPPROTO_TCP;
	int filter = DDOS_FILTER_TCP;
    int fd = open_bpf_map(file_verdict);
   	int nr_cpus = libbpf_num_possible_cpus(); 
	while ((opt = getopt_long(argc, argv, "hor",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'o': /* shared: --stats && --sec */
            break;
		case 'r':
            repeat = 1;
			break;
		case 'h':
		fail_opt:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	fd_verdict = open_bpf_map(file_verdict);

	
	/* Catch non-option arguments */
	if (argv[optind] != NULL) {
		fprintf(stderr, "ERR: Unknown non-option argument: %s\n",
			argv[optind]);
		goto fail_opt;
	}

    if(!repeat){
    printf("%-12s","CPU");
    for (int i = 0; i< NUM_CPUS; i++){
        printf(",CPU_%-d",i);
    }
    printf("\n");

    __u64 values[nr_cpus];
	for (int i = 0; i < XDP_ACTION_MAX; i++) {
        printf("%-12s",action2str(i));
        if ((bpf_map_lookup_elem(fd, &i, values)) != 0) {
			    fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X, setting -1\n", i);
        }
		for(int j = 0;j<NUM_CPUS;j++){
            printf(",%-25llu",values[j]);
        }
        printf("\n");
	}
 

	// TODO: implement stats for verdicts
	// Hack: keep it open to inspect /proc/pid/fdinfo/3
	close(fd_verdict);
    return 0;
    }
    
    else{
			//printf("work until here\n");
	
	out = fopen("xdpstats.csv","w+");

    if( out == NULL ) {
    	fprintf(stderr, "Couldn't open file: %s\n", strerror(errno));
    exit(1);
	}
	fdglob = fileno(out);
	//write(fdglob,"Hallo",5);
	//printf("work until here2\n");
	int interval = 1;
    for (int i = 0; i < XDP_ACTION_MAX; i++) {
        for (int j = 0; j< NUM_CPUS; j++){
            outbufferlen=snprintf(outbuffer,254,"%s_%d,",action2str(i),j);
			write(fdglob,outbuffer,outbufferlen);
        }
		
    }
	outbufferlen=snprintf(outbuffer,254,"Period\n");
	write(fdglob,outbuffer,outbufferlen);
    //fprintf(out,"%-10s","Period\n");
	//fclose(out);
    stats_poll(interval);
    }
}
