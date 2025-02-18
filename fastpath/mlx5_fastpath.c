#include <linux/module.h>
#include <linux/mlx5/fs.h>
#include "en.h"
#include "en/port.h"
#include "en/fs.h"
#include "fs_core.h"
#include "lib/fs_ttc.h"

struct mlx5e_hairpin {
	struct mlx5_hairpin *pair;

	struct mlx5_core_dev *func_mdev;
	struct mlx5e_priv *func_priv;
	u32 tdn;
	struct mlx5e_tir direct_tir;

	int num_channels;
	struct mlx5e_rqt indir_rqt;
	struct mlx5e_tir indir_tir[MLX5E_NUM_INDIR_TIRS];
	struct mlx5_ttc_table *ttc;
};

static struct mlx5e_hairpin *
mlx5e_hairpin_create(struct mlx5e_priv *priv, struct mlx5_hairpin_params *params,
		     int peer_ifindex);

static struct mlx5e_hairpin **hp_array = NULL;
void **rft_array = NULL;
EXPORT_SYMBOL(rft_array);

struct mlx5_flow_table* get_mlx5_root_table(int ifindex)
{
    return rft_array[ifindex];
}

static unsigned int get_mlx5e_hairpin_tir_num(struct mlx5e_priv *priv, int ifindex)
{
    struct mlx5e_hairpin *hp;
    if (hp_array[ifindex])
        return hp_array[ifindex]->direct_tir.tirn;

    struct mlx5_hairpin_params params;
    u64 link_speed64;
    u32 link_speed;

    params.log_data_size = 16;
    params.log_data_size = min_t(u8, params.log_data_size,
                        MLX5_CAP_GEN(priv->mdev, log_max_hairpin_wq_data_sz));
    params.log_data_size = max_t(u8, params.log_data_size,
                        MLX5_CAP_GEN(priv->mdev, log_min_hairpin_wq_data_sz));

    params.log_num_packets = params.log_data_size -
                    MLX5_MPWRQ_MIN_LOG_STRIDE_SZ(priv->mdev);
    params.log_num_packets = min_t(u8, params.log_num_packets,
                        MLX5_CAP_GEN(priv->mdev, log_max_hairpin_num_packets));

    params.q_counter = priv->q_counter;
    mlx5e_port_max_linkspeed(priv->mdev, &link_speed);
    link_speed = max_t(u32, link_speed, 50000);
    link_speed64 = link_speed;
    do_div(link_speed64, 50000);
    params.num_channels = link_speed64;

    hp = mlx5e_hairpin_create(priv, &params, ifindex);
    if (!hp)
    {
        printk("mlx5e_hairpin_create faild\n");
        return 0;
    }

    hp_array[ifindex] = hp;
    return hp_array[ifindex]->direct_tir.tirn;
}

unsigned int add_conntrack_mlx5_rule(
    __be32 sip,
    __be32 dip,
    __be16 sport,
    __be16 dport,
    u_int8_t protonum,
    unsigned char* dmac,
    struct net_device *in,
    struct net_device *out,
    void **ct_table,
    void **ct_rule,
    void **ct_fc
)
{
    struct mlx5e_priv *priv = netdev_priv(in);
    struct mlx5_flow_table* ft = get_mlx5_root_table(in->ifindex);
    if (!ft)
    {
        printk("\t - get_mlx5_root_table faild\n");
        return -1;
    }
    
    // printk("sip:%x dip:%x sport:%d dport:%d protonum:%d dmac:%x%x%x%x%x%x in_index:%d out_index:%d",
    //     sip, dip, sport, dport, protonum, dmac[0], dmac[1],dmac[2],dmac[3],dmac[4],dmac[5], in->ifindex, out->ifindex);
    // printk("\t - ft->id:%x\n", ft->id);
    // printk("\t - ft->ns:%lx\n", (unsigned long)ft->ns);

    struct mlx5_flow_act flow_act = {};
    flow_act.action = MLX5_FLOW_CONTEXT_ACTION_COUNT | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST | MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
    flow_act.flags  = FLOW_ACT_NO_APPEND;
    struct mlx5_flow_destination dest[2] = {};
    struct mlx5_fc *fc = mlx5_fc_create(priv->mdev, true);
    
    struct mlx5_flow_spec spec = {};
    spec.match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

    void *headers_c = MLX5_ADDR_OF(fte_match_param, &spec.match_criteria, outer_headers);
    void *headers_v = MLX5_ADDR_OF(fte_match_param, &spec.match_value, outer_headers);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
    MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);
    MLX5_SET(fte_match_set_lyr_2_4, headers_c, cvlan_tag, 1);
    
    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, src_ipv4_src_ipv6.ipv4_layout.ipv4);
    memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, src_ipv4_src_ipv6.ipv4_layout.ipv4), &sip, sizeof(sip));
    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
    memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, dst_ipv4_dst_ipv6.ipv4_layout.ipv4), &dip, sizeof(dip));

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
    memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, ip_protocol), &protonum, sizeof(protonum));
    switch (protonum)
    {
        case IPPROTO_TCP: 
        {
            MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_sport);
            memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, tcp_sport), &sport, sizeof(sport));
            MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, tcp_dport);
            memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, tcp_dport), &dport, sizeof(dport));
            break;
        }
        case IPPROTO_UDP: 
        {
            MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_sport);
            memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, udp_sport), &sport, sizeof(sport));
            MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
            memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, udp_dport), &dport, sizeof(dport));
            break;
        }
        default: break;
    }

    void *modify_actions = kcalloc(1, MLX5_MH_ACT_SZ * 3, GFP_KERNEL);
    memset(modify_actions, 0, MLX5_MH_ACT_SZ * 3);

    MLX5_SET(set_action_in, modify_actions, action_type, MLX5_ACTION_TYPE_SET);
    MLX5_SET(set_action_in, modify_actions, field, MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16);
    MLX5_SET(set_action_in, modify_actions, offset, 0);
    MLX5_SET(set_action_in, modify_actions, length, 32);
    MLX5_SET(set_action_in, modify_actions, data, (dmac[0] << 24 | dmac[1] << 16 | dmac[2] << 8 | dmac[3]));

    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, action_type, MLX5_ACTION_TYPE_SET);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, field, MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, offset, 0);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, length, 16);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, data, (dmac[4] << 8 | dmac[5]));

    flow_act.modify_hdr = mlx5_modify_header_alloc(mlx5e_fs_get_mdev(priv->fs), MLX5_FLOW_NAMESPACE_KERNEL,
                                              2, modify_actions);
    if (IS_ERR(flow_act.modify_hdr))
    {
        printk("mlx5_modify_header_alloc failed: %ld\n", PTR_ERR(flow_act.modify_hdr));
        return -2;
    }

    dest[0].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
    dest[0].tir_num = get_mlx5e_hairpin_tir_num(priv, out->ifindex);
    dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
    dest[1].counter_id = mlx5_fc_id(fc);

    struct mlx5_flow_handle *rule = mlx5_add_flow_rules(ft, &spec, &flow_act, dest, 2);
    if (IS_ERR(rule))
    {
        printk("\t mlx5_add_flow_rules faild - %ld\n", PTR_ERR(rule));
        return -3;
    }

    *ct_fc = fc;
    *ct_table = ft;
    *ct_rule = rule;
    return 0;
}
EXPORT_SYMBOL(add_conntrack_mlx5_rule);

void del_conntrack_mlx5_rule(struct mlx5_flow_handle *handle)
{
    mlx5_del_flow_rules(handle);
}
EXPORT_SYMBOL(del_conntrack_mlx5_rule);


void get_fc_query_count(struct mlx5_fc *counter, u64 *bytes, u64 *packets, u64 *lastuse)
{
    mlx5_fc_query_cached(counter, bytes, packets, lastuse);
    return ;
}
EXPORT_SYMBOL(get_fc_query_count);

void init_root_table(void)
{
    rft_array = kmalloc(sizeof(void*) * 10, GFP_KERNEL);
    hp_array = kmalloc(sizeof(void*) * 10, GFP_KERNEL);

    struct mlx5e_priv *priv = NULL;
    struct net_device *netdev = dev_get_by_name(&init_net, "eth1");
    if (netdev)
        priv = netdev_priv(netdev);

    struct mlx5_flow_namespace *ns;
    struct mlx5_flow_table_attr ft_attr;
    struct mlx5_flow_table *ft;

    ft_attr.max_fte = 0;
    ft_attr.level = 0;
    ft_attr.prio = 0;
    ft_attr.autogroup.max_num_groups = 4;
    ft_attr.autogroup.num_reserved_entries = 2;

    ns = mlx5_get_flow_namespace(priv->mdev, MLX5_FLOW_NAMESPACE_KERNEL);
    ft = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
    if (IS_ERR(ft))
        printk("PTR_ERR(ft):%ld\n", PTR_ERR(ft));

    rft_array[netdev->ifindex] = ft;
    {
        printk("\t--\t netdev->ifindex:%x\n", netdev->ifindex);
        printk("\t--\t ft->id:%x\n", ft->id);
        printk("\t--\t ft->ns:%lx\n", (unsigned long)ft->ns);
        printk("\t--\t ft->level:%d\n", ft->level);
        printk("\t--\t ft->max_fte:%d\n", ft->max_fte);
        printk("\t--\t ft->type:%d\n", ft->type);
        printk("\t--\t ft->flags:%u\n", ft->flags);
        printk("\t--\t ft->vport:%u\n", ft->vport);

        printk("\t--\t ft->autogroup.active:%d\n", ft->autogroup.active);
        printk("\t--\t ft->autogroup.group_size:%d\n", ft->autogroup.group_size);
        printk("\t--\t ft->autogroup.num_groups:%d\n", ft->autogroup.num_groups);
        printk("\t--\t ft->autogroup.max_fte:%d\n", ft->autogroup.max_fte);
        printk("\t--\t ft->autogroup.required_groups:%d\n", ft->autogroup.required_groups);
    }

    netdev = dev_get_by_name(&init_net, "eth2");
    if (netdev)
        priv = netdev_priv(netdev);

    ft_attr.max_fte = 0;
    ft_attr.level = 0;
    ft_attr.prio = 0;
    ft_attr.autogroup.max_num_groups = 4;
    ft_attr.autogroup.num_reserved_entries = 2;
    ns = mlx5_get_flow_namespace(priv->mdev, MLX5_FLOW_NAMESPACE_KERNEL);
    ft = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
    if (IS_ERR(ft))
        printk("PTR_ERR(ft):%ld\n", PTR_ERR(ft));

    rft_array[netdev->ifindex] = ft;
    {
        printk("\t--\t netdev->ifindex:%x\n", netdev->ifindex);
        printk("\t--\t ft->id:%x\n", ft->id);
        printk("\t--\t ft->ns:%lx\n", (unsigned long)ft->ns);
        printk("\t--\t ft->level:%d\n", ft->level);
        printk("\t--\t ft->max_fte:%d\n", ft->max_fte);
        printk("\t--\t ft->type:%d\n", ft->type);
        printk("\t--\t ft->flags:%u\n", ft->flags);
        printk("\t--\t ft->vport:%u\n", ft->vport);

        printk("\t--\t ft->autogroup.active:%d\n", ft->autogroup.active);
        printk("\t--\t ft->autogroup.group_size:%d\n", ft->autogroup.group_size);
        printk("\t--\t ft->autogroup.num_groups:%d\n", ft->autogroup.num_groups);
        printk("\t--\t ft->autogroup.max_fte:%d\n", ft->autogroup.max_fte);
        printk("\t--\t ft->autogroup.required_groups:%d\n", ft->autogroup.required_groups);
    }
}
EXPORT_SYMBOL(init_root_table);
