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
 
#include "libbpf.h"


#include "xdp_ddos01_blacklist_common.h"

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"add",		no_argument,		NULL, 'a' },
	{"del",		no_argument,		NULL, 'd' },
	{"subnet",		required_argument,	NULL, 's' },
    {0, 0, NULL,  0 }
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

int main (int argc, char **argv)
{
#	define STR_MAX 40 /* For trivial input validation */
	char _ip_string_buf[STR_MAX] = {};
	char *ip_string = NULL;

	unsigned int action = 0;
	int fd_subnetblacklist;
	int fd_subnetcache;
	#ifdef LONGTERM
	int fd_subnetblacklist_debug;
	#endif
	int longindex = 0;
	int opt;
	 

	while ((opt = getopt_long(argc, argv, "adshi:t:u:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'a':
			action = 1;
			break;
		case 'd':
			action = 2;
			break;
		case 's':
			if (!optarg || strlen(optarg) >= STR_MAX) {
				printf("ERR: src ip too long or NULL\n");
				goto fail_opt;
			}
			ip_string = (char *)&_ip_string_buf;
			strncpy(ip_string, optarg, STR_MAX);
			break;
		 
		case 'h':
		fail_opt:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
 	/* Update blacklist */ 
	if (action) {
		int res = 0; 

		if (!ip_string) {
			fprintf(stderr,
			  "ERR: action require type+data, e.g option --subnet\n");
			goto fail_opt;  
		}

		if (ip_string) { 
			struct in6_addr addr6;
			printf("IP String: %s\n",ip_string);
			if (inet_pton(AF_INET6, ip_string, &addr6) == 1) {
				// subnet blocking V1
				/*fd_subnetblacklist = open_bpf_map(file_blacklist_ipv6_subnet);
				res = blacklist_subnet_modify(fd_subnetblacklist, ip_string, action);
				close(fd_subnetblacklist);
				*/
				//subnet blocking V2
				fd_subnetcache = open_bpf_map(file_blacklist_ipv6_subnetcache);
				fd_subnetblacklist = open_bpf_map(file_blacklist_ipv6_subnet);
				res = blacklist_subnet_modify(fd_subnetcache,fd_subnetblacklist, ip_string, action);
				close(fd_subnetblacklist);
				#ifdef LONGTERM
				if (action == 1){
				fd_subnetblacklist_debug = open_bpf_map(file_blacklist_ipv6_subnet_debug);
				res = blacklist_subnet_modify(fd_subnetcache,fd_subnetblacklist_debug, ip_string, action);
				close(fd_subnetblacklist_debug);
				}
				#endif
				close(fd_subnetcache);

			}
			else{
				__u32 ipv4_addr;
				if(inet_pton(AF_INET, ip_string, &ipv4_addr)==1){
					//valid ipv4, don't care
					return 0;
				};
				fprintf(stderr, "ERR: IP address subnet isn't valid IPv6: %s\n",ip_string);
				exit(EXIT_FAIL_IP); 
			}
		} 
		return res;
	}

	/* Catch non-option arguments */
	if (argv[optind] != NULL) {
		fprintf(stderr, "ERR: Unknown non-option argument: %s\n",
			argv[optind]);
		goto fail_opt;
	}
}
