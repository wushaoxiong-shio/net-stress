#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// 定义一个 map 用于存储源 IP 和目标 IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key_size, sizeof(__be32));
    __type(value_size, sizeof(__be32));
} ip_rcv_map SEC(".maps");


SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv)
{

    return 0;
}

char _license[] SEC("license") = "GPL";