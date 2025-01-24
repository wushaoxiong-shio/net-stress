#include "en.h"
#include "fs_core.h"
#include <linux/module.h>
#include <linux/mlx5/fs.h>
#include "en/fs.h"
#include "en/port.h"

struct mlx5_fc_cache {
	u64 packets;
	u64 bytes;
	u64 lastuse;
};


struct mlx5_fc {
	struct list_head list;
	struct llist_node addlist;
	struct llist_node dellist;

	u64 lastpackets;
	u64 lastbytes;

	struct mlx5_fc_bulk *bulk;
	u32 id;
	bool aging;

	struct mlx5_fc_cache cache ____cacheline_aligned_in_smp;
};

struct mlx5_fc *fc = NULL;
struct mlx5e_priv *priv = NULL;
struct mlx5_flow_table *ft = NULL;
struct mlx5_flow_handle *rule = NULL;

struct mlx5e_hairpin *
mlx5e_hairpin_create(struct mlx5e_priv *priv, struct mlx5_hairpin_params *params,
		     int peer_ifindex);

int init_mlx5_priv(void)
{
    struct net_device *netdev = dev_get_by_name(&init_net, "eth1");
    if (netdev)
        priv = netdev_priv(netdev);

    return 0;
}


static int __init conntrack_fastpath_init(void)
{
    int err = 0;

    init_mlx5_priv();
    struct mlx5_flow_namespace *ns;
    struct mlx5_flow_table_attr ft_attr;

    ft_attr.max_fte = 0;
    ft_attr.level = 0;
    ft_attr.prio = 0;
    ft_attr.autogroup.max_num_groups = 4;
    ft_attr.autogroup.num_reserved_entries = 2;

    ns = mlx5_get_flow_namespace(priv->mdev, MLX5_FLOW_NAMESPACE_KERNEL);
    ft = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
    if (IS_ERR(ft))
    {
        printk("PTR_ERR(ft):%ld\n", PTR_ERR(ft));
        goto err;
    }

    printk("\t mlx5e_create_flow_steering\n");
    printk("\t--\t ft->id:%x\n", ft->id);
    printk("\t--\t ft->ns:%x\n", ft->ns);
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
   
    u32 src_ip = 0x0A010101;
    struct mlx5_flow_act flow_act =
    {
        .action = MLX5_FLOW_CONTEXT_ACTION_COUNT | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST | MLX5_FLOW_CONTEXT_ACTION_MOD_HDR,
        // .action = MLX5_FLOW_CONTEXT_ACTION_COUNT | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
        .flags  = FLOW_ACT_NO_APPEND,
    };
    struct mlx5_flow_spec specd = {};
    struct mlx5_flow_spec *spec = &specd;
    struct mlx5_flow_destination dest[2] = {};
    fc = mlx5_fc_create(priv->mdev, true);

    void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
    void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
    MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);

    MLX5_SET(fte_match_set_lyr_2_4, headers_c, cvlan_tag, 1);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, src_ipv4_src_ipv6.ipv4_layout.ipv4);
    memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, src_ipv4_src_ipv6.ipv4_layout.ipv4), &src_ip, sizeof(src_ip));

    specd.match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

    void *modify_actions = kcalloc(1, MLX5_MH_ACT_SZ * 3, GFP_KERNEL);;
    memset(modify_actions, 0, MLX5_MH_ACT_SZ * 3);

    MLX5_SET(set_action_in, modify_actions, action_type, MLX5_ACTION_TYPE_SET);
    MLX5_SET(set_action_in, modify_actions, field, MLX5_ACTION_IN_FIELD_OUT_DMAC_47_16);
    MLX5_SET(set_action_in, modify_actions, offset, 0);
    MLX5_SET(set_action_in, modify_actions, length, 32);
    MLX5_SET(set_action_in, modify_actions, data, ntohl(0x506b4bef));

    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, action_type, MLX5_ACTION_TYPE_SET);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, field, MLX5_ACTION_IN_FIELD_OUT_DMAC_15_0);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, offset, 0);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, length, 16);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ, data, ntohs(0xfc19));

    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ * 2, action_type, MLX5_ACTION_TYPE_SET);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ * 2, field, MLX5_ACTION_IN_FIELD_OUT_SIPV4);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ * 2, offset, 0);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ * 2, length, 32);
    MLX5_SET(set_action_in, modify_actions + MLX5_MH_ACT_SZ * 2, data, ntohl(0x02020202));

    flow_act.modify_hdr = mlx5_modify_header_alloc(mlx5e_fs_get_mdev(priv->fs), MLX5_FLOW_NAMESPACE_KERNEL,
                                              3, modify_actions);
    if (IS_ERR(flow_act.modify_hdr))
    {
        err = PTR_ERR(flow_act.modify_hdr);
        printk("mlx5_modify_header_alloc failed: %ld\n", PTR_ERR(flow_act.modify_hdr));
        goto err;
    }

    struct mlx5_hairpin_params params;
    struct mlx5e_hairpin *hp;
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

	hp = mlx5e_hairpin_create(priv, &params, 4);

    dest[0].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
    dest[0].tir_num = 29;
    dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
    dest[1].counter_id = mlx5_fc_id(fc);

    rule = mlx5_add_flow_rules(ft, spec, &flow_act, dest, 2);
    if (IS_ERR(rule))
    {
        printk("\t - %ld\n", PTR_ERR(rule));
        goto err;
    }

    return 0;

err:
    mlx5_destroy_flow_table(ft);
    return err;
}


static void __exit conntrack_fastpath_exit(void)
{
    u64 bytes, packets, lastuse;
    struct mlx5_fc_cache c;
	c = fc->cache;
	bytes = c.bytes - fc->lastbytes;
	packets = c.packets - fc->lastpackets;
	lastuse = c.lastuse;
	fc->lastbytes = c.bytes;
	fc->lastpackets = c.packets;
    printk("bytes:%llu packets:%llu lastuse:%llu\n", bytes, packets, lastuse);

    mlx5_del_flow_rules(rule);
    mlx5_destroy_flow_table(ft);
	ft = NULL;

    return ;
}


module_init(conntrack_fastpath_init);
module_exit(conntrack_fastpath_exit);

MODULE_LICENSE("GPL");