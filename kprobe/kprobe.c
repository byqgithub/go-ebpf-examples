//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <asm/ptrace.h>
#include <stdio.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
// #include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// struct bpf_map_def SEC("maps") kprobe_map = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(__u32),
// 	.value_size  = sizeof(__u64),
// 	.max_entries = 1,
// };

// SEC("kprobe/sys_execve")
// int kprobe_execve() {
// 	__u32 key     = 0;
// 	__u64 initval = 1, *valp;

// 	valp = bpf_map_lookup_elem(&kprobe_map, &key);
// 	if (!valp) {
// 		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
// 		return 0;
// 	}
// 	__sync_fetch_and_add(valp, 1);

// 	return 0;
// };

/***********************************************/

#ifndef NAME_LEN_MAX
#define NAME_LEN_MAX 16
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10);
	__type(key, char[NAME_LEN_MAX]);
	__type(value, __u32);
} kprob_cgroup_name SEC(".maps");

SEC("kprobe/cgroup_mkdir")
int record_cgroup_mkdir(struct pt_regs *ctx) {
	char *parm2 = (char*)PT_REGS_PARM2(ctx);
	char name[NAME_LEN_MAX] = "\0";
	long ret = bpf_probe_read_kernel_str(name, sizeof(name), parm2);
	if (ret < 0) {
		bpf_printk("Error in bpf_probe_read_kernel_str: %d\n", ret);
		return 1;
	}

	__u32 *count = bpf_map_lookup_elem(&kprob_cgroup_name, name);
	if (!count) {
		__u32 init_count = 1;
		long result = bpf_map_update_elem(&kprob_cgroup_name, name, &init_count, BPF_ANY);
		if (result) {
			bpf_printk("Error in record_cgroup_mkdir bpf_map_update_elem: %d\n", result);
		} else {
			// bpf_printk("cgroup_mkdir name: %s\n", name);
		}
	}

	return 0;
}

SEC("kprobe/cgroup_rmdir")
int record_cgroup_rmdir(struct pt_regs *ctx) {
	// struct kernfs_node *kn = (struct kernfs_node *)PT_REGS_PARM1(ctx);
	// char *point = "cgroup_rmdir\0";
	char name[NAME_LEN_MAX] = "cgroup_rmdir\0";
	// long num = bpf_probe_read_kernel_str(name, sizeof(name), point);
	// if (num < 0) {
	// 	bpf_printk("Error in record_cgroup_rmdir bpf_probe_read_kernel_str: %d\n", num);
	// 	return 1;
	// } else {
	// 	bpf_printk("cgroup_rmdir name: %s\n", name);
	// }

	__u32 *count = bpf_map_lookup_elem(&kprob_cgroup_name, name);
	if (!count) {
		__u32 init_count = 1;
		long result = bpf_map_update_elem(&kprob_cgroup_name, name, &init_count, BPF_ANY);
		if (result) {
			bpf_printk("Error in record_cgroup_mkdir bpf_map_update_elem: %d\n", result);
		} else {
			bpf_printk("cgroup_mkdir name: %s\n", name);
		}
	} else {
		__sync_fetch_and_add(count, 1);
	}

	return 0;
}
