//go:build ignore

// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_core_read.h>
// #include <stdio.h>
// #include <linux/pkt_cls.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <asm/ptrace.h>

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "common.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * For CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common is the minimal network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock_common.
 * This copy contains only the fields needed for this example to
 * fetch the source and destination port numbers and IP addresses.
 */
// struct sock_common {
// 	union {
// 		struct {
// 			// skc_daddr is destination IP address
// 			__be32 skc_daddr;
// 			// skc_rcv_saddr is the source IP address
// 			__be32 skc_rcv_saddr;
// 		};
// 	};
// 	union {
// 		struct {
// 			// skc_dport is the destination TCP/UDP port
// 			__be16 skc_dport;
// 			// skc_num is the source TCP/UDP port
// 			__u16 skc_num;
// 		};
// 	};
// 	// skc_family is the network address family (2 for IPV4)
// 	short unsigned int skc_family;
// } __attribute__((preserve_access_index));

/**
 * struct sock is the network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock.
 * This copy is needed only to access struct sock_common.
 */
// struct sock {
// 	struct sock_common __sk_common;
// } __attribute__((preserve_access_index));

/**
 * struct tcp_sock is the Linux representation of a TCP socket.
 * This is a simplified copy of the kernel's struct tcp_sock.
 * For this example we only need srtt_us to read the smoothed RTT.
 */
// struct tcp_sock {
// 	__u32 srtt_us;
// } __attribute__((preserve_access_index));

// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 1 << 24);
// } events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
// struct event {
// 	__u16 sport;
// 	__u16 dport;
// 	__u32 saddr;
// 	__u32 daddr;
// 	__u32 srtt;
// };
// struct event *unused_event __attribute__((unused));

// SEC("fentry/tcp_close")
// int BPF_PROG(tcp_close, struct sock *sk) {
// 	if (sk->__sk_common.skc_family != AF_INET) {
// 		return 0;
// 	}

// 	// The input struct sock is actually a tcp_sock, so we can type-cast
// 	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
// 	if (!ts) {
// 		return 0;
// 	}

// 	struct event *tcp_info;
// 	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
// 	if (!tcp_info) {
// 		return 0;
// 	}

// 	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
// 	tcp_info->daddr = sk->__sk_common.skc_daddr;
// 	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
// 	tcp_info->sport = sk->__sk_common.skc_num;

// 	tcp_info->srtt = ts->srtt_us >> 3;
// 	tcp_info->srtt /= 1000;

// 	bpf_ringbuf_submit(tcp_info, 0);

// 	return 0;
// }

/******************************************************/
#ifndef MAP_MAX_NUM
#define MAP_MAX_NUM 16
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_NUM);
	__type(key, __u32);
	__type(value, char[TASK_COMM_LEN]);
} pid_comm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_NUM);
	__type(key, __u32);
	__type(value, __u64);
} upload_traffic SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_MAX_NUM);
	__type(key, __u32);
	__type(value, __u64);
} download_traffic SEC(".maps");


static __always_inline int static_pkg_count(void *map, __u32 *key, __u32 *len, char *type) {
    __u64 *pkt_count = bpf_map_lookup_elem(map, key);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u64 init_pkt_count = (__u64)(*len);
		bpf_map_update_elem(map, key, &init_pkt_count, BPF_ANY);
        bpf_printk("[%s] Add key: %u, count: %llu", type, *key, init_pkt_count);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, (__u64)(*len));
        bpf_printk("[%s] key: %u, total count: %llu", type, *key, *pkt_count);
	}

    return 0;
}

static __always_inline int store_pid_comm(void *map, __u32 *pid, char *comm) {
	char *value = bpf_map_lookup_elem(map, pid);
	if (!value) {
		bpf_map_update_elem(map, pid, comm, BPF_ANY);
		bpf_printk("Add pid: %u, comm: %s", *pid, comm);
	}
	return 0;
}

// 利用 classid 过滤数据包，累计数据包大小
static __always_inline int filter_skb(struct sk_buff *skb, void *map, char *type) {
	if (!skb) {
        return 1; // Invalid skb
    }

	// 获取当前的 PID 和 TGID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;  // 高 32 位是 TGID（进程 ID）
    __u32 pid = pid_tgid & 0xFFFFFFFF;  // 低 32 位是 PID（线程 ID）
	// bpf_printk("Current TGID: %u, PID: %u\n", tgid, pid);
	if (pid <= 0) {
		// pid == 0 不统计
		return 1;
	}

	char comm[TASK_COMM_LEN] = "\0";
	__u64 errno = bpf_get_current_comm(comm, sizeof(comm));
	if (errno != 0) {
		bpf_printk("[%s] Failed to get process name, err no: %ull\n", type, errno);
		return 1;
    }
	store_pid_comm(&pid_comm, &pid, comm);

    // 读取 skb->len
    __u32 pkt_len = 0;
    __u64 err = bpf_probe_read_kernel(&pkt_len, sizeof(pkt_len), &skb->len);
	if (err != 0) {
		bpf_printk("[%s] bpf probe read kernel skb len error: %d", type, err);
		return 1;
	}
	static_pkg_count(map, &pid, &pkt_len, type);

	return 0;
}

SEC("kprobe/ip_rcv")
int statistic_upload_flow(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    char *type = "in";
	filter_skb(skb, &download_traffic, type);

	return 0;
}

SEC("kprobe/ip_output")
int statistic_download_flow(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
    char *type = "out";
	filter_skb(skb, &upload_traffic, type);

	return 0;
}