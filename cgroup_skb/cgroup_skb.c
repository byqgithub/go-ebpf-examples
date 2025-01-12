//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// struct bpf_map_def SEC("maps") pkt_count = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(__u32),
// 	.value_size  = sizeof(__u64),
// 	.max_entries = 1,
// };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} pkt_count SEC(".maps");

// SEC("cgroup_skb/egress")
SEC("cgroup/skb")
int count_egress_packets(struct __sk_buff *skb) {
	__u32 key      = 0;
	__u64 init_val = 1;

	__u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
	if (!count) {
		bpf_map_update_elem(&pkt_count, &key, &init_val, BPF_ANY);
		return 1;
	}
	__sync_fetch_and_add(count, 1);

	// __u32 classid = bpf_skb_cgroup_classid(skb);
	// bpf_printk("classid %u", classid);

	return 1;
}