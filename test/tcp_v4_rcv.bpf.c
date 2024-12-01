#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} tcp_v4_rcv_map SEC(".maps");


SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb)
{

    unsigned int key = 0;
    unsigned int value = 0;
    struct iphdr iph;
    struct tcphdr tcph;

    __be32 src_ip;
    __be32 dst_ip;

    unsigned char *head;
    bpf_probe_read(&head, sizeof(unsigned char *), &skb->head);

    __u16 network_header;
    bpf_probe_read(&network_header, sizeof(__u16), &skb->network_header);
    bpf_probe_read(&iph, sizeof(struct iphdr), head + network_header);

    __u16 transport_header;
    bpf_probe_read(&transport_header, sizeof(__u16), &skb->transport_header);
    bpf_probe_read(&tcph, sizeof(struct tcphdr), head + transport_header);

    src_ip = iph.saddr;
    dst_ip = iph.daddr;

    if ((tcph.dest) == bpf_htons(22))
    {
        // cat /sys/kernel/debug/tracing/trace_pipe
        bpf_printk("Source IP: %u.%u.%u.%u, Dest IP: %u.%u.%u.%u source:%u dest:%u\n",
            (bpf_ntohl(src_ip) >> 24) & 0xFF,
            (bpf_ntohl(src_ip) >> 16) & 0xFF,
            (bpf_ntohl(src_ip) >> 8) & 0xFF,
            (bpf_ntohl(src_ip)) & 0xFF,
            (bpf_ntohl(dst_ip) >> 24) & 0xFF,
            (bpf_ntohl(dst_ip) >> 16) & 0xFF,
            (bpf_ntohl(dst_ip) >> 8) & 0xFF,
            (bpf_ntohl(dst_ip)) & 0xFF,
            bpf_ntohs(tcph.source), bpf_ntohs(tcph.dest)
        );
    }

    value = bpf_ntohs(tcph.source);
    bpf_map_update_elem(&tcp_v4_rcv_map, &key, &value, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";