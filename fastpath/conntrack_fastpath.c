#include <linux/module.h>
#include <linux/mlx5/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include "net/netfilter/nf_conntrack_core.h"
#include "net/netfilter/nf_conntrack_zones.h"
#include <net/netfilter/nf_conntrack_extend.h>


typedef int (*xdp_fastpath_fn)(void *tuple, unsigned char* dmac, int *ifindex);
extern xdp_fastpath_fn xdp_fastpath_fn_ptr __rcu;

struct mlx5_rule_data {
    struct delayed_work work;
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    u_int8_t protonum;
    unsigned char dmac[6];
    struct net_device *in;
    struct net_device *out;
    void **ft;
    void **rule;
    void **fc;
    enum fastpath_status *status;
};

enum fastpath_status
{
    NONE_FAST = 0,
    TRY_MLX5,
    XDP_FAST,
    MLX5_FAST
};

struct nf_conn_fastpath {
    enum fastpath_status status[IP_CT_DIR_MAX];
    unsigned char dmac[IP_CT_DIR_MAX][6];
    int out_idx[IP_CT_DIR_MAX];
    void *ft[IP_CT_DIR_MAX];
    void *rule[IP_CT_DIR_MAX];
    void *fc[IP_CT_DIR_MAX];
};

static inline struct nf_conn_fastpath *nf_ct_fastpath_ext_add(struct nf_conn *ct, gfp_t gfp)
{
    return nf_ct_ext_add(ct, NF_CT_EXT_FASTPATH, gfp);
}

inline struct nf_conn_fastpath *nf_conn_fastpath_find(const struct nf_conn *ct)
{
    return nf_ct_ext_find(ct, NF_CT_EXT_FASTPATH);
}
EXPORT_SYMBOL(nf_conn_fastpath_find);

int xdp_fastpath(void *tuple, unsigned char* dmac, int *ifindex)
{
    int err = 0;
    u32 zone_id;
    struct nf_conn *ct = NULL;
    struct nf_conn_fastpath *fp = NULL;
    struct nf_conntrack_tuple_hash *h = NULL;
    const struct nf_conntrack_zone *zone = &nf_ct_zone_dflt;
    zone_id = nf_ct_zone_id(zone, IP_CT_DIR_ORIGINAL);
    h = nf_conntrack_find_get(&init_net, zone, tuple);
    if (!h)
    {
        err = 1;
        goto no_match;
    }

    ct = nf_ct_tuplehash_to_ctrack(h);
    if (!ct)
    {
        err = 2;
        goto no_match;
    }

    fp = nf_conn_fastpath_find(ct);
    if (!fp || fp->status[h->tuple.dst.dir] != XDP_FAST)
    {
        err = 3;
        goto no_match;
    }

    memcpy(dmac, fp->dmac[h->tuple.dst.dir], 6);
    *ifindex = fp->out_idx[h->tuple.dst.dir];
    WRITE_ONCE(ct->timeout, nfct_time_stamp + (30 * HZ));
    // printk("dmac:%x%x%x%x%x%x ifindex:%d\n", dmac[0],dmac[1],dmac[2],dmac[3],dmac[4],dmac[5],*ifindex);

no_match:
    nf_ct_put(ct);
    // printk("xdp_fastpath err:%d\n", err);
    return err;
}


void dwork_add_conntrack_mlx5_rule(struct work_struct *work)
{
    struct mlx5_rule_data *data = container_of(work, struct mlx5_rule_data, work.work);
    int ret = add_conntrack_mlx5_rule(
        data->sip, data->dip,
        data->sport, data->dport,
        data->protonum,
        data->dmac,
        data->in, data->out,
        data->ft, data->rule, data->fc
    );

    if (ret)
    {
        printk("add_conntrack_mlx5_rule faild set to XDP_FAST\n");
        *(data->status) = XDP_FAST;
        return;
    }
    *(data->status) = MLX5_FAST;
    return;
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
        neigh = ip_neigh_for_gw(rt, skb, &is_gw);
	    if (IS_ERR(neigh))
        {
            printk("\t -- IS_ERR(neigh\n");
            return NF_ACCEPT;
        }

        memcpy(fp->dmac[CTINFO2DIR(ctinfo)], neigh->ha, 6);
        fp->out_idx[CTINFO2DIR(ctinfo)] = state->out->ifindex;
        fp->status[CTINFO2DIR(ctinfo)] = XDP_FAST;

        WRITE_ONCE(ct->timeout, nfct_time_stamp + (300 * HZ));

        struct mlx5_rule_data *data = kmalloc(sizeof(struct mlx5_rule_data), GFP_KERNEL);
        data->sip = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u3.ip;
        data->dip = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u3.ip;
        data->sport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u.all;
        data->dport = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.u.all;
        data->protonum = ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.dst.protonum;
        memcpy(data->dmac, neigh->ha, 6);
        data->in = state->in;
        data->out = state->out;
        data->ft = &fp->ft[CTINFO2DIR(ctinfo)];
        data->fc = &fp->fc[CTINFO2DIR(ctinfo)];
        data->rule = &fp->rule[CTINFO2DIR(ctinfo)];
        data->status = &fp->status[CTINFO2DIR(ctinfo)];

        INIT_DELAYED_WORK(&data->work, dwork_add_conntrack_mlx5_rule);
        fp->status[CTINFO2DIR(ctinfo)] = TRY_MLX5;
        schedule_delayed_work(&data->work, 1 * HZ);
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
    rcu_assign_pointer(xdp_fastpath_fn_ptr, xdp_fastpath);
    synchronize_rcu();
    nf_register_net_hooks(&init_net, &conntrack_fastpath_ops, 1);
    return 0;
}


static void __exit conntrack_fastpath_exit(void)
{
    nf_unregister_net_hooks(&init_net, &conntrack_fastpath_ops, 1);
    rcu_assign_pointer(xdp_fastpath_fn_ptr, NULL);
    synchronize_rcu();
    nf_ct_netns_put(&init_net, NFPROTO_INET);
}


module_init(conntrack_fastpath_init);
module_exit(conntrack_fastpath_exit);
MODULE_LICENSE("GPL");