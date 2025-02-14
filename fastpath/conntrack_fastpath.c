#include "net/netfilter/nf_conntrack_extend.h"
#include <linux/module.h>
#include "net/netfilter/nf_conntrack.h"
#include "linux/netfilter_ipv4.h"
#include "linux/netfilter.h"
#include <linux/mlx5/fs.h>

enum fastpath_status
{
    NONE_FAST = 0,
    XDP_FAST,
    MLX5_FAST
};

struct nf_conn_fastpath {
	enum fastpath_status status[IP_CT_DIR_MAX];
};

static inline struct nf_conn_fastpath *nf_ct_fastpath_ext_add(struct nf_conn *ct, gfp_t gfp)
{
	return nf_ct_ext_add(ct, NF_CT_EXT_FASTPATH, gfp);
};

static inline struct nf_conn_fastpath *nf_conn_fastpath_find(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_FASTPATH);
}

static unsigned int conntrack_fastpath(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
    struct nf_conn_fastpath *fp = NULL;

	ct = nf_ct_get(skb, &ctinfo);
    if (!ct)
        return NF_ACCEPT;

    fp = nf_conn_fastpath_find(ct);
    if (!fp)
    {
        printk("\t -- nf_ct_fastpath_ext_add ctinfo:%d\n", ctinfo);
        fp = nf_ct_fastpath_ext_add(ct, GFP_ATOMIC);
        fp->status[IP_CT_DIR_ORIGINAL] = NONE_FAST;
        fp->status[IP_CT_DIR_REPLY] = NONE_FAST;
    }

    if (fp && nf_ct_is_confirmed(ct) 
            && (ctinfo == IP_CT_ESTABLISHED || ctinfo == IP_CT_ESTABLISHED_REPLY) 
            && fp->status[CTINFO2DIR(ctinfo)] == NONE_FAST)
    {
        struct rtable *rt = (struct rtable *)skb_dst(skb);
        struct neighbour *neigh;
        bool is_gw = false;

        rcu_read_lock();
        neigh = ip_neigh_for_gw(rt, skb, &is_gw);
	    if (IS_ERR(neigh))
            printk("\t -- IS_ERR(neigh\n");
        
        rcu_read_unlock();
        printk("\t\t\t -- neigh->ha:%x%x%x%x%x%x\n", neigh->ha[0],neigh->ha[1],neigh->ha[2],neigh->ha[3],neigh->ha[4],neigh->ha[5]);

        add_conntrack_mlx5_rule(
            ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u3.ip,
            ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u3.ip,
            ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u.all,
            ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u.all,
            ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.protonum,
            neigh->ha,
            state->in, state->out
        );
        fp->status[CTINFO2DIR(ctinfo)] = MLX5_FAST;
        printk("add_conntrack_mlx5_rule -- end\n");
    }
    return NF_ACCEPT;
}

static const struct nf_hook_ops conntrack_fastpath_ops = {
    .hook		= conntrack_fastpath,
    .pf		= NFPROTO_IPV4,
    .hooknum	= NF_INET_FORWARD,
    .priority	= NF_IP_PRI_MANGLE,
};


static int __init conntrack_fastpath_init(void)
{
    nf_ct_netns_get(&init_net, NFPROTO_INET);
    init_root_table();

    nf_register_net_hooks(&init_net, &conntrack_fastpath_ops, 1);

    return 0;
}


static void __exit conntrack_fastpath_exit(void)
{

}


module_init(conntrack_fastpath_init);
module_exit(conntrack_fastpath_exit);
MODULE_LICENSE("GPL");