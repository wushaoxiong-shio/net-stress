#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

static int (*bpf_xdp_fastpath)(void* tuple, unsigned char* dmac, int *ifindex) = (void*) BPF_FUNC_xdp_fastpath;

SEC("xdp")
int xdp_fastpath(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 eth_proto = eth->h_proto;
    if (eth_proto != 0x0008)
        return XDP_PASS;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    // bpf_printk("Source IP: %u.%u.%u.%u, Dest IP: %u.%u.%u.%u\n",
    //     (bpf_ntohl(iph->saddr) >> 24) & 0xFF,
    //     (bpf_ntohl(iph->saddr) >> 16) & 0xFF,
    //     (bpf_ntohl(iph->saddr) >> 8) & 0xFF,
    //     (bpf_ntohl(iph->saddr)) & 0xFF,
    //     (bpf_ntohl(iph->daddr) >> 24) & 0xFF,
    //     (bpf_ntohl(iph->daddr) >> 16) & 0xFF,
    //     (bpf_ntohl(iph->daddr) >> 8) & 0xFF,
    //     (bpf_ntohl(iph->daddr)) & 0xFF
    // );

    int ifindex;
    unsigned char dmac[6];
    struct nf_conntrack_tuple tuple;

    memset(&tuple, 0, sizeof(struct nf_conntrack_tuple));
    tuple.src.l3num = NFPROTO_IPV4;
    tuple.dst.dir = IP_CT_DIR_ORIGINAL;
    tuple.dst.protonum = iph->protocol;
    tuple.src.u3.ip = iph->saddr;
    tuple.dst.u3.ip = iph->daddr;

    switch (iph->protocol)
    {
        case IPPROTO_ICMP : 
        {
            struct icmphdr *hp = (void*)(iph + 1);
            if ((void*)(hp + 1) > data_end)
                return XDP_PASS;

            tuple.dst.u.icmp.type = hp->type;
            tuple.src.u.icmp.id = hp->un.echo.id;
            tuple.dst.u.icmp.code = hp->code;
            break;
        };
        case IPPROTO_TCP : 
        {
            struct udphdr *udph =  (void*)(iph + 1);
            if ((void*)(udph + 1) > data_end)
                return XDP_PASS;

            tuple.src.u.udp.port = udph->source;
            tuple.dst.u.udp.port = udph->dest;
            break;
        }
        case IPPROTO_UDP : 
        {
            struct tcphdr *tcph = (void*)(iph + 1);
            if ((void*)(tcph + 1) > data_end)
                return XDP_PASS;

            tuple.src.u.tcp.port = tcph->source;
            tuple.dst.u.tcp.port = tcph->dest;
            break;
        };
        default: return XDP_PASS;
    }

    int ret = bpf_xdp_fastpath(&tuple, dmac, &ifindex);
    
    if (ret)
        return XDP_PASS;

    // bpf_printk("dmac:%x%x%x%x%x%x ifindex:%d\n", dmac[0],dmac[1],dmac[2],dmac[3],dmac[4],dmac[5],ifindex);
    memcpy(eth->h_dest, dmac, 6);
    return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";