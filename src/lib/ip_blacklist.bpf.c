/*  XDP example: DDoS protection via IPv4 blacklist
 *
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 *  Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
//#define DEBUG 1
//#define SUBNET 1
//#define LONGTERM 1
#define NULL ((void *)0)
#define SUBNET_THRESHOLD 3
//#define KBUILD_MODNAME "foo"
#include <stdbool.h>
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <tools/lib/bpf/bpf_helpers.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



enum {
	DDOS_FILTER_TCP = 0,
	DDOS_FILTER_UDP,
	DDOS_FILTER_MAX,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};
struct ipv6_frag_hdr {
	unsigned int nexthdr: 8;
	unsigned int reserved: 8;
	unsigned int fragment: 13;
	unsigned int res: 2;
	unsigned int more: 1;
	unsigned int identification:32;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,1000000);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} blacklistv4 SEC(".maps");
		

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,1000000);
  __type(key,__uint128_t);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);
// subnet v1: just one map for user/kernel value not counter!
} blacklistv6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,100000);
  __uint(map_flags,BPF_F_NO_PREALLOC);
  __type(key,__u64);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} blacklistv6subnet SEC(".maps");
// subnet v2: distinct caching map for subnet blocking. Value in v1 map is counter!!

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries,100000);
  __type(key,__u64);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} blacklistv6subnetcache SEC(".maps");
#ifdef DEBUG
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,17);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);
} verdict_reasons SEC(".maps");
#endif
#define XDP_ACTION_MAX (XDP_TX + 2)
/* Counter per XDP "action" verdict */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,XDP_ACTION_MAX);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);
} verdict_cnt SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,65536);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} port_blacklist SEC(".maps");
/* Counter per XDP "action" verdict */

/* TCP Drop counter */
/*struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,65536);
  __type(key,__u32);
  __type(value,__u64);

} port_blacklist_drop_count_tcp SEC(".maps");
*/
/* UDP Drop counter */
struct portmap {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,65536);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} port_blacklist_drop_count_tcp SEC(".maps"),port_blacklist_drop_count_udp SEC(".maps");

#ifdef LONGTERM
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,100000);
  __uint(map_flags,BPF_F_NO_PREALLOC);
  __type(key,__u32);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} blacklistv4_nodelete SEC(".maps");
		

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,100000);
  __uint(map_flags,BPF_F_NO_PREALLOC);
  __type(key,__uint128_t);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);
// subnet v1: just one map for user/kernel value not counter!
} blacklistv6_nodelete SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries,100000);
  __uint(map_flags,BPF_F_NO_PREALLOC);
  __type(key,__u64);
  __type(value,__u64);
  __uint(pinning,LIBBPF_PIN_BY_NAME);

} blacklistv6subnet_nodelete SEC(".maps");
#endif
static inline struct portmap *drop_count_by_fproto(int fproto) {

	switch (fproto) {
	case DDOS_FILTER_UDP:
		return &port_blacklist_drop_count_udp;
		break;
	case DDOS_FILTER_TCP:
		return &port_blacklist_drop_count_tcp;
		break;
	}
	return NULL;
	}

// TODO: Add map for controlling behavior

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Keeps stats of XDP_DROP vs XDP_PASS */
static //__always_inline
void stats_action_verdict(__u32 action)
{
	__u64 *value;

	if (action >= XDP_ACTION_MAX)
		return;

	value = bpf_map_lookup_elem(&verdict_cnt, &action);
	if (value)
		*value += 1;
}
#ifdef DEBUG
static __always_inline
void stats_action_reason(__u32 key)
{
	__u64 *value=0;
	bpf_map_update_elem(&verdict_reasons,&key,&value,BPF_NOEXIST);
	value = bpf_map_lookup_elem(&verdict_reasons, &key);
	if (value)
		*value += 1;
}
#endif

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static //__always_inline
__u32 parse_eth(struct ethhdr *eth, void *data_end,
	       __u16 *eth_proto, __u64 *l3_offset)
{
	__u16 eth_type;
	__u64 offset;
	//__u32 action = XDP_PASS;

	offset = sizeof(*eth);
	if ((void*)eth + offset > data_end){
		#ifdef DEBUG
		stats_action_reason(0);
		#endif
		return XDP_ABORTED;
	}
	eth_type = eth->h_proto;
	bpf_debug("Debug: eth_type:0x%x\n", bpf_ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if ((bpf_ntohs(eth_type) < ETH_P_802_3_MIN)){
		#ifdef DEBUG
		stats_action_reason(1);
		#endif
		return XDP_PASS;
		}

	/* Handle VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end){
			#ifdef DEBUG
			stats_action_reason(2);
			#endif
			return XDP_ABORTED;
			}
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end){
			#ifdef DEBUG
			stats_action_reason(3);
			#endif
			return XDP_ABORTED;
			}
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = bpf_ntohs(eth_type);
	*l3_offset = offset;
	return 5;
}

static //__always_inline
__u32 parse_port(struct xdp_md *ctx, __u8 proto, void *hdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udph;
	struct tcphdr *tcph;
	__u32 *value;
	__u64 *drops;
	__u32 dport;
	__u32 dport_idx;
	__u32 fproto;

	switch (proto) {
	case IPPROTO_UDP:
		udph = hdr;
		if ((void*) udph + sizeof(*udph) > data_end) {
		        bpf_debug("Invalid UDP packet.\n");
			#ifdef DEBUG
			stats_action_reason(8);
			#endif
			return XDP_ABORTED;
		}
		dport = bpf_ntohs(udph->dest);
		fproto = DDOS_FILTER_UDP;
		break;
	case IPPROTO_TCP:
		tcph = hdr;
		if ((void*) tcph +sizeof(*tcph) > data_end) {
		        bpf_debug("Invalid TCP packet.\n");
			#ifdef DEBUG
			stats_action_reason(9);
			#endif
			return XDP_ABORTED;
		}
		dport = bpf_ntohs(tcph->dest);
		fproto = DDOS_FILTER_TCP;
		break;
	default:
		#ifdef DEBUG
		stats_action_reason(7);
		#endif
		return XDP_PASS;
	}

	dport_idx = dport;
	bpf_debug("Dest Port is: %d\n",dport_idx);
	value = bpf_map_lookup_elem(&port_blacklist, &dport_idx);

	if (value) {
		if (*value & (1 << fproto)) {
			struct portmap *drop_counter = drop_count_by_fproto(fproto);
			if (drop_counter) {
				drops = bpf_map_lookup_elem(drop_counter , &dport_idx);
				if (drops)
					*drops += 1; // Keep a counter for drop matches
			}
			#ifdef DEBUG
			stats_action_reason(10);
			#endif
			return XDP_DROP;
		}
		// value will be not NULL if the map exists, same result as key = 9
		//reason = 10;
		//stats_action_reason(reason);
		//return XDP_PASS;
		}
	#ifdef DEBUG
	stats_action_reason(9);
	#endif
	return XDP_PASS;	
}

static //__always_inline
__u32 parse_ipv4(struct xdp_md *ctx, __u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	__u64 *value;
	__u32 ip_src; /* type need to match map */

	/* Hint: +1 is sizeof(struct iphdr) */
	if ((void*)iph + sizeof(*iph) > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		#ifdef DEBUG
		stats_action_reason(5);
		#endif
		return XDP_ABORTED;
	}
	/* Extract key */
	ip_src = iph->saddr;
	//ip_src = ntohl(ip_src); // ntohl does not work for some reason!?!

  if ((ip_src & __constant_htonl(0xFFFFFF00)) == __constant_htonl(0x0A031E00)) {
    int action = XDP_ACTION_MAX-1;
    value = bpf_map_lookup_elem(&verdict_cnt, &action);
    if (value)
      *value += 1;
  }
  bpf_debug("Valid IPv4 packet: raw saddr:0x%x\n", ip_src);

	value = bpf_map_lookup_elem(&blacklistv4, &ip_src);
	if (value) {
		#ifdef LONGTERM
		value = bpf_map_lookup_elem(&blacklistv4_nodelete,  &ip_src); /30 MILLION IS MOST INTERESTING/&ip_src);
		#endif
		/* Don't need __sync_fetch_and_add(); as percpu map */
	        *value += 1; /* Keep a counter for drop matches */
		#ifdef DEBUG
		stats_action_reason(6);
		#endif
		return XDP_DROP;
	}
	return XDP_PASS;
	return parse_port(ctx, iph->protocol, iph + 1);
}


static //__always_inline
__u32 parse_ipv6(struct xdp_md *ctx, __u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;


	struct ipv6hdr *ip6h = data + l3_offset;	
	__u64 *value=0;
	__u64 subnet_key=0;
	__u64 l4_offset = l3_offset;
	__u8 protocol;
	//unsigned __int128 ip_src; /* type need to match map */
	//__u8 ip_src[16];
	if ((void*) ip6h +sizeof(*ip6h) > data_end) {
		bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
		; //this is here to supress warning in non-debug mode when bpf_debug is disabled
		#ifdef DEBUG
		stats_action_reason(11);
		#endif
		return XDP_ABORTED;
	}
	/* Extract key */
	//memcpy(ip_src,ip6h->saddr.in6_u.u6_addr8,sizeof(ip_src));
	//bpf_debug("IPv6 address: %016lX%016lX\n",&(ip6h->saddr.in6_u.u6_addr8),&(ip6h->saddr.in6_u.u6_addr8)+8*sizeof(__u8));
	/*bpf_debug("IPv6 address: %02X%02X", ip6h->saddr.in6_u.u6_addr8[0],ip6h->saddr.in6_u.u6_addr8[1]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[2],ip6h->saddr.in6_u.u6_addr8[3]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[4],ip6h->saddr.in6_u.u6_addr8[5]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[6],ip6h->saddr.in6_u.u6_addr8[7]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[8],ip6h->saddr.in6_u.u6_addr8[9]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[10],ip6h->saddr.in6_u.u6_addr8[11]);
	bpf_debug("%02X%02X", ip6h->saddr.in6_u.u6_addr8[12],ip6h->saddr.in6_u.u6_addr8[13]);
	bpf_debug("%02X%02X\n", ip6h->saddr.in6_u.u6_addr8[14],ip6h->saddr.in6_u.u6_addr8[15]);
	*/

	value = bpf_map_lookup_elem(&blacklistv6, &ip6h->saddr.in6_u.u6_addr8); //&ip_src);
	if (value) {
		bpf_debug("dropcounter value %llu\n", *value);//,subnet_key>>32);
		#ifdef LONGTERM
		value = bpf_map_lookup_elem(&blacklistv6_nodelete, &ip6h->saddr.in6_u.u6_addr8); //&ip_src);
		#endif
		*value += 1; /* Keep a counter for drop matches */
		#ifdef DEBUG
		stats_action_reason(12);
		#endif
		return XDP_DROP;
	}

	//ipv6 subnet_blocking
	#ifdef SUBNET
	memcpy(&subnet_key,ip6h->saddr.in6_u.u6_addr8,sizeof(__u64));
		bpf_debug("/64 prefix %016lX\n", subnet_key);//,subnet_key>>32);
	#endif
	// v1
	/*value = bpf_map_lookup_elem(&blacklistv6subnet, &subnet_key); //&ip_src);

	if (value){
	bpf_debug("subnet incident value %llu\n", *value);//,subnet_key>>32);
		if (*value>= SUBNET_THRESHOLD) {
			stats_action_reason(13);
			return XDP_DROP;
		}
	}
	*/
	//v2
	#if defined SUBNET && !defined LONGTERM
	value = bpf_map_lookup_elem(&blacklistv6subnet, &subnet_key); //&ip_src);
	#endif
	#ifdef SUBNET
	if (value) {
		#if defined SUBNET && defined LONGTERM 
		value = bpf_map_lookup_elem(&blacklistv6subnet_nodelete, &subnet_key); //&ip_src);
		#endif
		*value += 1; // Keep a counter for drop matches 
		#ifdef DEBUG
		stats_action_reason(13);
		#endif
		return XDP_DROP;
	}
	#endif
	l4_offset += sizeof(*ip6h);
	protocol = ip6h->nexthdr;
	bpf_debug("L4 offset %llu\n", l4_offset);
	; //this is here to supress warning in non-debug mode when bpf_debug is disabled
	bpf_debug("IPv6 Next Header:%u\n", protocol);

       
	// Parsing Extension Headers:
	for (int i = 0; i<10; i++) {
		// unassigned/experimental values
		if (protocol > 143){
			#ifdef DEBUG
		  stats_action_reason(14);
		  #endif
		  return XDP_DROP;
		}
		switch (protocol) {
			
			// IPv6 fragmentation header
			case 44: // Fragment (fixed size, 8 bytes)
				;
				struct ipv6_frag_hdr *ip6fraghdr = data + l4_offset;
				if ( (void*) ip6fraghdr +sizeof(*ip6fraghdr) > data_end) {
					bpf_debug("Invalid IPv6 fragmentation header");
					#ifdef DEBUG
					stats_action_reason(15);
					#endif
					return XDP_ABORTED;
				}
				protocol = ip6fraghdr->nexthdr;
				bpf_debug("IPv6 Fragment Header: next Header, %u",protocol);
				l4_offset += sizeof(*ip6fraghdr);
				continue;
			// IPv6 extension headers
			case 0: //Hop by hop
			case 43: //Routing info
			case 51: // Authentication 
			case 60: // Destination Options (max 2x)
			case 135: // Mobility
			case 139: // Host identiy
			case 140: // Shim6
				;
				struct ipv6_opt_hdr *ip6exthdr = data + l4_offset;
				//if(ip6exthdr + sizeof(ip6exthdr+ip6exthdr->hdrlen)> data_end){
				if ((void*) ip6exthdr + sizeof((ip6exthdr->hdrlen)*8 +8) > data_end) {
					bpf_debug("Invalid IPv6 extension header");
					#ifdef DEBUG
					stats_action_reason(16);
					#endif
					return XDP_ABORTED;
				}
				protocol = ip6exthdr->nexthdr;
				bpf_debug("IPv6 extension found: Size hdrlen: %d\n",ip6exthdr->hdrlen);
				; //this is here to supress warning in non-debug mode when bpf_debug is disabled
				bpf_debug("IPv6 extension found: Size %d\n",sizeof(*ip6exthdr));
				; //this is here to supress warning in non-debug mode when bpf_debug is disabled
				bpf_debug("IPv6 extension found: Next Header:%u\n", protocol);
				; //this is here to supress warning in non-debug mode when bpf_debug is disabled
				l4_offset += (ip6exthdr->hdrlen)*8 + 8; // leading 8 octectc is not part of hdrlen, hdrlen is in unit: 8 octets 
				continue;
			// L4 Protocols we look at
			case 6: //TCP
			case 17: //UDP
	                default:
				return parse_port(ctx, protocol, data+l4_offset);
		}
	}
	// Too many extension headers
	bpf_debug("IPv6 too many extension headers.\n");
	#ifdef DEBUG
	stats_action_reason(15);
	#endif
	return XDP_DROP;	
}

static //__always_inline
__u32 handle_eth_protocol(struct xdp_md *ctx, __u16 eth_proto, __u64 l3_offset)
{	
	switch (eth_proto) {
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6: /* Not handler for IPv6 yet*/
		return parse_ipv6(ctx, l3_offset);
		break;
	case ETH_P_ARP:  /* Let OS handle ARP */
		/* Fall-through */
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		#ifdef DEBUG
		stats_action_reason(4);
		#endif
		return XDP_PASS;
	}
	#ifdef DEBUG
	stats_action_reason(4);
	#endif
	return XDP_PASS;
}

SEC("xdp")
int  xdp_prog(struct xdp_md *ctx)
{
  //stats_action_verdict(XDP_DROP);
  //return XDP_DROP;
        void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 eth_proto = 0;
	__u64 l3_offset = 0;
        __u32 action = XDP_PASS;

	action = parse_eth(eth, data_end, &eth_proto, &l3_offset);
		if (action < 5) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		stats_action_verdict(action);
		return action; /* Skip */
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

	action = handle_eth_protocol(ctx, eth_proto, l3_offset);
	stats_action_verdict(action);
	return action;
}

char _license[] SEC("license") = "GPL";
