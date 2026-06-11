#ifndef __XDP_DDOS01_BLACKLIST_COMMON_H
#define __XDP_DDOS01_BLACKLIST_COMMON_H
//#define DEBUG 1
//#define LONGTERM 1
//#define SUBNET
#define SUBNET_THRESHOLD 3

// added header by Philipp
#include <cstdlib>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>

#include <time.h>
#include <bpf/libbpf.h>
#include <stdbool.h>

#include "common.h" 

/* Export eBPF map for IPv4 blacklist as a file
 * Gotcha need to mount:
 *   mount -t bpf bpf /sys/fs/bpf/
 */
static const char *file_blacklist_ipv4 = "/sys/fs/bpf/blacklistv4";
static const char *file_blacklist_ipv6 = "/sys/fs/bpf/blacklistv6";
static const char *file_verdict   = "/sys/fs/bpf/verdict_cnt";
static const char *file_blacklist_ipv6_subnet   = "/sys/fs/bpf/blacklistv6subnet";
static const char *file_blacklist_ipv6_subnetcache = "/sys/fs/bpf/blacklistv6subnetcache";

/* gettime returns the current time of day in nanoseconds.
 * Cost: clock_gettime (ns) => 26ns (CLOCK_MONOTONIC)
 *       clock_gettime (ns) =>  9ns (CLOCK_MONOTONIC_COARSE)
 */
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

/* Blacklist operations */
#define ACTION_ADD	1
#define ACTION_DEL	2

enum {
	DDOS_FILTER_TCP = 0,
	DDOS_FILTER_UDP,
	DDOS_FILTER_MAX
};

// copied function here from xdp_ddos01_blacklist_common.c by Philipp and made static
static int open_bpf_map(const char *file)
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

// modifies either the IPv4 blacklist or IPv6 blacklist
static int blacklist_modify(int fd, void *ip, unsigned int action)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	int res = -1;
	
	memset(values, 0, sizeof(__u64) * nr_cpus);
	if (action == ACTION_ADD) { // add IP to blacklist
    res = bpf_map_update_elem(fd, ip, values, BPF_NOEXIST);
		if (res == 0) {
			printf("Action add: Added IP to blacklist.\n");
		}
	} else if (action == ACTION_DEL) { // del IP from blacklist
    res = bpf_map_delete_elem(fd, ip);
		if (res == 0) {
			printf("Action delete: Removed IP from blacklist.\n");
		}
	} else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n", __func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { /* 0 == success */
		// if (iptype == 4){
		// 	fprintf(stderr,
		// 	"%s() IP:%s key:0x%X errno(%d/%s)",
		// 	__func__, ip_string, key4, errno, strerror(errno));
		// 			}
		// else if (iptype == 6){
		// 	fprintf(stderr,
		// 	"%s() IP:%s key:0x%llX%llX errno(%d)",
		// 	__func__, ip_string, (__u64)key6,(__u64)(key6>>64), errno); //strerror(errno));	
		// 		}
		

		if (errno == 17) {
			#ifndef LONGTERM
			fprintf(stderr, ": Already in blacklist\n");
			#endif 
			return EXIT_OK;
		}
		fprintf(stderr, "\n");
		return EXIT_FAIL_MAP_KEY;
	}

	return EXIT_OK;
}

// Subnet blocking v2
// modifies the subnet cache and, if threshold reached or subnet cache key deleted, subnet blacklist
// ACTION_ADD: increases the subnet cache count
// ACTION_DEL: decreases the subnet cache count
// static int blacklist_subnet_modify(int fd_cache, int fd_subnetblacklist, char *ip_string, unsigned int action, bool *blacklist_modified) {
// 	int nr_cpus = libbpf_num_possible_cpus();
// 	__u64 verdict_values[nr_cpus]; // per cpu map for subnet blacklist
// 	__u64 value_prev = 0;
// 	__u64 value_next = 0;
//
// 	memset(verdict_values, 0,  sizeof(__u64) * nr_cpus);
//
// 	unsigned __int128 key6;
// 	__u64 subnet_key;
// 	int res;
//
// 	// convert IPv6 string into binary representation
// 	res = inet_pton(AF_INET6, ip_string, &key6);
// 	if (res <= 0) {
// 		if (res == 0) {
// 			fprintf(stderr,
// 				"Error: IPv6 \"%s\" not in presentation format\n",
// 				ip_string);
// 		} else {
// 			perror("inet_pton");
// 			return EXIT_FAIL_IP;
// 		}
// 	}
// 	
// 	// only /64 subnet of ip address needed
// 	subnet_key = (__u64) key6;
//
// 	if (action == ACTION_ADD) {
// 		res = bpf_map_lookup_elem(fd_cache, &subnet_key, &value_prev);
// 		if (res < 0) { // subnet not yet cached -> add subnet to cache
// 			value_next = 1;
// 			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_NOEXIST);
// 			if (res == -1) {
// 				goto map_error;			
// 			}
// 		} else { // subnet already cached -> increase subnet cache value
// 			value_next = value_prev + 1;
// 			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
// 			if (res == -1) {
// 				goto map_error;			
// 			}
// 		}
//
// 		if (value_next == SUBNET_THRESHOLD) { // if threshold reached -> add IP to subnet blacklist
// 			// TODO: this will fail if the threshold is reached again after ACTION_DEL lead to value_next 
// 			// falling below threshold, but not yet deleting the key from blacklist
// 			res = bpf_map_update_elem(fd_subnetblacklist,&subnet_key,&verdict_values,BPF_NOEXIST);
// 			if (res == -1) {
// 				goto map_error;				
// 			}
//
// 			*blacklist_modified = true;
// 			printf("Action add: Added subnet to blacklist, after reaching defined threshold.\n");
// 		}
// 	} else if (action == ACTION_DEL) { 
// 		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
// 		if (value_prev > 0) {
// 			value_next = value_prev - 1;
// 		}
// 		if (res < 0) { // fd_cache entry does not exist
// 			res = bpf_map_lookup_elem(fd_subnetblacklist, &subnet_key, &verdict_values);
// 			if (res < 0) {
// 				// nothing to do, both entries do not exist anyway
// 			} else {
// 				// fd_cache entry does not exist, but fd_subnetblacklist entry does
// 				goto map_error;
// 			}
// 		} else { // fd_cache entry exists
// 			// current implementation only unblocks subnet when subnet cache count reaches 0 again
// 			if (value_next == 0) { // subnet removed again from cache and blacklist
// 				res = bpf_map_delete_elem(fd_cache, &subnet_key);
// 				if (res < 0) {
// 					goto map_error;			
// 				}
// 				res = bpf_map_lookup_elem(fd_subnetblacklist, &subnet_key, &verdict_values);
// 				if (res < 0) {
// 					// blacklist entry already deleted? both entries, cache and blacklist, should be deleted 
// 					// at the same time
// 					goto map_error;
// 				} else { 
// 					res = bpf_map_delete_elem(fd_subnetblacklist,&subnet_key); // delete subnet key
// 					if (res < 0) {
// 						goto map_error;
// 					}
//
// 					*blacklist_modified = true;
// 					printf("Action delete: Removed subnet from blacklist again, after deleting cache entry.\n");
// 				}
// 			} else { // decrease subnet cache value
// 				res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
// 				if (res < 0) {
// 					goto map_error;
// 				}
// 			}
// 		}
// 	} else {
// 		fprintf(stderr, "Error: %s() invalid action 0x%x\n",
// 			__func__, action);
//
// 		return EXIT_FAIL_OPTION;
// 	}
//
// 	printf("Subnet cache value changed for key %s/64: %llu -> %llu\n", ip_string, value_prev, value_next);
// 	return EXIT_OK;
//
// map_error:
// 	fprintf(stderr,
// 			"%s() IP:%s key:0x%016llX errno(%d)\n",
// 			__func__, ip_string,subnet_key, errno);
// 	return EXIT_FAIL_MAP_KEY;
// }
#endif
