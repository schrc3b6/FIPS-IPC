#include "include/ebpf_utils.h"



bool glob_verbose = false;

int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	
	return fd;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !glob_verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static inline int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		return EXIT_FAIL;
	}
	return EXIT_OK;
}

int ebpf_cleanup(const char * device, bool unpin, bool verbose){

    struct ip_blacklist_bpf * skel;
	int if_index;

	if(verbose) {
		/* Set up libbpf errors and debug info callback */
		libbpf_set_print(libbpf_print_fn);
		glob_verbose = true;
	}
	else 
	{
		glob_verbose = false;
	}

	if ((if_index = if_nametoindex(device)) == 0)
	{
		fprintf(stderr,"Looking up device index for device %s failed: %s\n", device, strerror(errno));
 		return EXIT_FAIL;
	}

    /* Detach, indpendent of program. Call succeeds even on an empty device */
	
	if (bpf_xdp_attach(if_index, -1, XDP_FLAGS_DRV_MODE, NULL)) 
	{
		fprintf(stderr, "Failed to detach eBPF program in xdp driver mode from device: %s. See libbpf error. Doing skb mode instead.\n",device);

		if (bpf_xdp_attach(if_index, -1, XDP_FLAGS_SKB_MODE, NULL)) 
		{
			fprintf(stderr, "Failed to detach eBPF program in xdp skb mode from device: %s. See libbpf error. Exiting.\n",device);
			return EXIT_FAIL;
		}

	}
	
    if(unpin){

        if ((skel = ip_blacklist_bpf__open()) == NULL) 
		{
            fprintf(stderr, "Failed to open BPF skeleton\n");
        	return EXIT_FAIL;
        }
        if (bpf_object__unpin_maps(skel->obj,NULL)) {
            fprintf(stderr, "Failed to unpin maps in /sys/fs/bpf: %s\n",strerror(errno));
			return EXIT_FAIL;
        }
    }
    
    return EXIT_OK;
		
}


int ebpf_setup(const char * device, bool verbose){

    struct ip_blacklist_bpf *skel;

    if(verbose) {
		/* Set up libbpf errors and debug info callback */
		libbpf_set_print(libbpf_print_fn);
		glob_verbose = true;
	}
	else 
	{
		glob_verbose = false;
	}

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	if(bump_memlock_rlimit())
	{
		return EXIT_FAIL;
	}

	/* Check if device exists */
	int err, if_index;

	if ((if_index = if_nametoindex(device)) == 0)
	{
 		fprintf(stderr,"Looking up device index for device %s failed: %s\n", device, strerror(errno));
		return EXIT_FAILURE;
	}

    unsigned int xdp_fd;

	/* Check if the program is already loaded */
    if((bpf_xdp_query_id(if_index, 0, &xdp_fd)) != -1)
	{
        ebpf_cleanup(device, false, verbose);
    }
    
	if ((skel = ip_blacklist_bpf__open()) == NULL) 
	{
		fprintf(stderr, "Failed to open BPF skeleton : %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* Load & verify BPF programs */
	if (ip_blacklist_bpf__load(skel)) 
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton : %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* Attach xdp */
	if ((err = bpf_xdp_attach(if_index, bpf_program__fd(skel->progs.xdp_prog), XDP_FLAGS_DRV_MODE, NULL))) 
	{
		if (err == -17)
		{
			fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error: %s. Device already in use in different mode. Trying skb mode.\n",device, strerror(errno));
		}
		else if(err ==-22)
		{
			fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device %s. See libbpf error: %s. Check device MTU. Jumboframes are not supported and throw this error\n",device, strerror(errno));
		}

		fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error: %s. Doing skb mode instead.\n",device, strerror(errno));

		if ((err = bpf_xdp_attach(if_index, bpf_program__fd(skel->progs.xdp_prog), XDP_FLAGS_SKB_MODE, NULL))) 
		{
			if (err == -17)
			{
				fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error. Device already in use.\n",device);
				ip_blacklist_bpf__destroy(skel);
				return EXIT_FAIL;
			}
			fprintf(stderr, "Failed to attach eBPF program in xdp skb mode for device: %s. See libbpf error. Exiting.\n",device);
			ip_blacklist_bpf__destroy(skel);
			return EXIT_FAIL;
		}

	}

	return EXIT_OK;

}
