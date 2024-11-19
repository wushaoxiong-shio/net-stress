#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} ip_rcv_map SEC(".maps");


SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb)
{

    unsigned int key = 0;
    unsigned int initial_value = 0;

    bpf_probe_read(&initial_value, sizeof(initial_value), &skb->truesize);

    // cat /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("skb->truesize: %u\n", initial_value);

    int ret = bpf_map_update_elem(&ip_rcv_map, &key, &initial_value, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";