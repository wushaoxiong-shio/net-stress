#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv)
{
    bpf_trace_printk("Hello, World!\n", sizeof("Hello, World!\n"));
    return 0;
}


char _license[] SEC("license") = "GPL";