#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ptrace.h>
#include <linux/net.h> 


// 定义一个 map 用于存储源 IP 和目标 IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key_size, sizeof(__be32));
    __type(value_size, sizeof(__be32));
} ip_rcv_map SEC(".maps");


SEC("kprobe/ip_rcv")
int bpf_kprobe_ip_rcv(struct pt_regs *ctx)
{
    struct __sk_buff *skb;
    struct iphdr *iph;
    __be32 src_ip, dest_ip;

    skb = (struct __sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb)
        return 0;

    if (skb->len < sizeof(struct iphdr)) 
        return 0;

    iph = (struct iphdr *)(skb->data);
    if (!iph)
        return 0;

    src_ip = iph->saddr;
    dest_ip = iph->daddr;

    bpf_map_update_elem(&ip_rcv_map, &src_ip, &dest_ip, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";