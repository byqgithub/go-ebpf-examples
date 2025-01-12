//go:build ignore

#include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
// #include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* Define an ARRAY map for storing ingress packet count */
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u64);
// 	__uint(max_entries, 1);
// } ingress_pkt_count SEC(".maps");

/* Define an ARRAY map for storing egress packet count */
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u64);
// 	__uint(max_entries, 1);
// } egress_pkt_count SEC(".maps");

/*
Upon arrival of each network packet, retrieve and increment
the packet count from the provided map.
Returns TC_ACT_OK, allowing the packet to proceed.
*/
// static __always_inline int update_map_pkt_count(void *map) {
// 	__u32 key    = 0;
// 	__u64 *count = bpf_map_lookup_elem(map, &key);
// 	if (count) {
// 		__sync_fetch_and_add(count, 1);
// 	}

// 	return TC_ACT_OK;
// }

// SEC("tc")
// int ingress_prog_func(struct __sk_buff *skb) {
// 	return update_map_pkt_count(&ingress_pkt_count);
// }

// SEC("tc")
// int egress_prog_func(struct __sk_buff *skb) {
// 	return update_map_pkt_count(&egress_pkt_count);
// }

/* ************************************************* */
#define MAX_MAP_ENTRIES 16

// Define an hash map for storing ingress packet count
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, MAX_MAP_ENTRIES);
} tc_ingress_pkt_count SEC(".maps");

// struct bpf_map_def tc_ingress_pkt_count SEC(".maps") = {
// 	.type = BPF_MAP_TYPE_LRU_HASH,
// 	.key_size = sizeof(__u64),
// 	.value_size = sizeof(__u64),
// 	.max_entries = MAX_MAP_ENTRIES
// };

// Define an hash map for storing egress packet count
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, MAX_MAP_ENTRIES);
} tc_egress_pkt_count SEC(".maps");

// struct bpf_map_def tc_egress_pkt_count SEC(".maps") = {
// 	.type = BPF_MAP_TYPE_LRU_HASH,
// 	.key_size = sizeof(__u64),
// 	.value_size = sizeof(__u64),
// 	.max_entries = MAX_MAP_ENTRIES
// };

/*
Attempt to parse the IPv4 address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_addr(struct __sk_buff *skb, __u32 *ip_src, __u32 *ip_dst) {
	void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    // Check packet's size
    // the pointer arithmetic is based on the size of data type, current_address plus int(1) means:
    // new_address= current_address + size_of(data type)
    if ((void *)(eth + 1) > data_end)
    {
        return 0;
    }

    // Check if Ethernet frame has IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // 不是 IPv4 数据包，可能数据未正确初始化
        return 0;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1); // or (struct iphdr *)( ((void*)eth) + ETH_HLEN );
    if ((void *)(iph + 1) > data_end) {
        return 0;
    }    

    // Return the source IP address and dst IP addr in network byte order.
    *ip_src = (__u32)(iph->saddr);
    *ip_dst = (__u32)(iph->daddr);
    return 1;
}

static __always_inline int static_pkg_count(void *map, __u32 *len, __u64 *key) {
    __u64 *pkt_count = bpf_map_lookup_elem(map, key);
    // __u64 *pkt_count = 0;
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u64 init_pkt_count = *len;
		bpf_map_update_elem(map, key, &init_pkt_count, BPF_ANY);
        bpf_printk("key: %d, count: %d", key, init_pkt_count);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, *len);
        bpf_printk("key: %u, count: %u", key, *len + pkt_count);
	}

    return 0;
}

SEC("ingress")
int tc_ingress_prog_func(struct __sk_buff *skb) {
	__u32 src_ip = 0;
	__u32 dst_ip = 0;
	if (!parse_ip_addr(skb, &src_ip, &dst_ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

    __u64 key = ((__u64)src_ip << 32) + dst_ip;
    // __u64 key = src_ip;
    static_pkg_count(&tc_ingress_pkt_count, &skb->len, &key);
    // __u64 key = ((__u64)src_ip << 32) + dst_ip;
    // __u64 *pkt_count = bpf_map_lookup_elem(&tc_ingress_pkt_count, &key);
	// if (!pkt_count) {
	// 	// No entry in the map for this IP address yet, so set the initial value to 1.
	// 	__u32 init_pkt_count = skb->len;
	// 	bpf_map_update_elem(&tc_ingress_pkt_count, &key, &init_pkt_count, BPF_ANY);
	// } else {
	// 	// Entry already exists for this IP address,
	// 	// so increment it atomically using an LLVM built-in.
	// 	__sync_fetch_and_add(pkt_count, skb->len);
	// }
done:
	return TC_ACT_OK;
}

SEC("egress")
int tc_egress_prog_func(struct __sk_buff *skb) {
	__u32 src_ip = 0;
	__u32 dst_ip = 0;
	__u32 classid = bpf_skb_cgroup_classid(skb);
	bpf_printk("classid %u", classid);
	if (!parse_ip_addr(skb, &src_ip, &dst_ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

    __u64 key = ((__u64)dst_ip << 32) + src_ip;
    // __u64 key = dst_ip;
    static_pkg_count(&tc_egress_pkt_count, &skb->len, &key);
    // __u64 key = ((__u64)src_ip << 32) + dst_ip;
    // __u32 *pkt_count = bpf_map_lookup_elem(&tc_egress_pkt_count, &key);
	// if (!pkt_count) {
	// 	// No entry in the map for this IP address yet, so set the initial value to 1.
	// 	__u32 init_pkt_count = skb->len;
	// 	bpf_map_update_elem(&tc_egress_pkt_count, &key, &init_pkt_count, BPF_ANY);
	// } else {
	// 	// Entry already exists for this IP address,
	// 	// so increment it atomically using an LLVM built-in.
	// 	__sync_fetch_and_add(pkt_count, skb->len);
	// }

done:
	return TC_ACT_OK;
}
