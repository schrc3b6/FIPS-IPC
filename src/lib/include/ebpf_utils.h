/**
 * Utility functions for loading and unloading the ip_blacklist eBPF program and related maps.
 * Code was adapted from the original implementation by Florian Mikolajczak (see thesis for literature reference)
 * 
*/
#pragma once
 
#ifndef __EBPF_UTILS_H
#define __EBPF_UTILS_H
#define _GNU_SOURCE 1
#include <stdbool.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <errno.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ip_blacklist.skel.h"

#define SUBNET_THRESHOLD 3

/* Exit return codes */
#define	EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_MAP		20
#define EXIT_FAIL_MAP_KEY	21
#define EXIT_FAIL_MAP_FILE	22
#define EXIT_FAIL_MAP_FS	23
#define EXIT_FAIL_IP		30
#define EXIT_FAIL_PORT		31
#define EXIT_FAIL_BPF		40
#define EXIT_FAIL_BPF_ELF	41
#define EXIT_FAIL_BPF_RELOCATE	42

// eBPF map paths
#define FILE_BLACKLIST_IPV4 "/sys/fs/bpf/blacklistv4"
#define FILE_BLACKLIST_IPV6 "/sys/fs/bpf/blacklistv6"
#define FILE_VERDICT "/sys/fs/bpf/verdict_cnt"
#define FILE_BLACKLIST_IPV6_SUBNET "/sys/fs/bpf/blacklistv6subnet"
#define FILE_BLACKLIST_IPV6_SUBNETCACHE "/sys/fs/bpf/blacklistv6subnetcache"

#define FILE_PORT_BLACKLIST "/sys/fs/bpf/port_blacklist";
#define FILE_PORT_BLACKLIST_COUNT_TCP "/sys/fs/bpf/port_blacklist_drop_count_tcp"
#define FILE_PORT_BLACKLIST_COUNT_UDP "/sys/fs/bpf/port_blacklist_drop_count_udp"

// Loads ebpf program to device and pins ebpf maps
int ebpf_setup(const char * device, bool verbose);

// Unloads ebpf program from device and (optionally) unpins ebpf maps
int ebpf_cleanup(const char * device, bool unpin, bool verbose);

// Opens a file descriptor for an eBPF map
int open_bpf_map(const char *file);


#endif
