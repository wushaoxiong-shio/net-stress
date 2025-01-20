#include "en.h"
#include <linux/module.h>
#include <linux/mlx5/fs.h>
#include "en/fs.h"

#include "fastpath.h"


struct mlx5e_priv *priv_eth1 = NULL;
struct mlx5e_priv *priv_eth2 = NULL;

struct mlx5e_conntrack_table *cht = NULL;

int init_mlx5_priv(void)
{
    struct net_device *netdev = dev_get_by_name(&init_net, "eth1");
    if (netdev)
        priv_eth1 = netdev_priv(netdev);

    netdev = NULL;
    netdev = dev_get_by_name(&init_net, "eth2");
    if (netdev)
        priv_eth2 = netdev_priv(netdev);

    if (!priv_eth1 || !priv_eth2)
        return -1;

    return 0;
}


static void mlx5e_destroy_groups_cp(struct mlx5e_flow_table *ft)
{
	int i;

	for (i = ft->num_groups - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(ft->g[i]))
			mlx5_destroy_flow_group(ft->g[i]);
		ft->g[i] = NULL;
	}
	ft->num_groups = 0;
}

static void mlx5e_destroy_flow_table_cp(struct mlx5e_flow_table *ft)
{
	mlx5e_destroy_groups_cp(ft);
	kfree(ft->g);
	mlx5_destroy_flow_table(ft->t);
	ft->t = NULL;
}

int create_flow_table(struct mlx5e_conntrack_table *cht)
{
    int err = 0;
    mlx5_create_flow_table_handler_ptr handler;

    cht->ft_attr.flags = MLX5_FLOW_TABLE_UNMANAGED;
    cht->ft_attr.max_fte = MLX5E_FS_CONNTRACK_TABLE_SIZE;
	cht->ft_attr.level = MLX5E_CONNTRACK_FT_LEVEL;
	cht->ft_attr.prio = MLX5E_NIC_PRIO;

    cht->ns = mlx5_get_flow_namespace(priv_eth1->mdev, MLX5_FLOW_NAMESPACE_KERNEL);

    rcu_read_lock();
    handler = rcu_dereference(mlx5_create_flow_table_handler);
    if (!handler)
    {
        printk("mlx5_create_ft_handler is NULL!\n");
        rcu_read_unlock();
        return -EINVAL;
    }
    rcu_read_unlock();

    cht->ft.t = handler(cht->ns, &cht->ft_attr);
    if (IS_ERR(cht->ft.t))
    {
		err = PTR_ERR(cht->ft.t);
		cht->ft.t = NULL;
        return err;
	}

    printk("Created fs def table id %x level %u max_fte %u\n", cht->ft.t->id, cht->ft.t->level, cht->ft.t->max_fte);

    return 0;
}

int create_table_groups(struct mlx5e_conntrack_table *cht)
{
    int err = 0;
    int ix = 0;
	u32 *in;
	u8 *mc;
    void *outer_headers_c;
    mlx5_create_flow_group_handler_ptr handler;

    int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);

    rcu_read_lock();
    handler = rcu_dereference(mlx5_create_flow_group_handler);
    if (!handler)
    {
        printk("mlx5_create_ft_handler is NULL!\n");
        rcu_read_unlock();
        return -EINVAL;
    }
    rcu_read_unlock();

    cht->ft.g = kcalloc(MLX5E_FS_CONNTRACK_NUM_GROUPS, sizeof(cht->ft.g), GFP_KERNEL);
    in = kvzalloc(inlen, GFP_KERNEL);
    if  (!in || !cht->ft.g)
    {
		kfree(cht->ft.g);
		cht->ft.g = NULL;
		kvfree(in);
		return -ENOMEM;
	}

    mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
    outer_headers_c = MLX5_ADDR_OF(fte_match_param, mc, outer_headers);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ethertype);
    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ip_protocol);
    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ip_version);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, src_ipv4_src_ipv6.ipv4_layout.ipv4);
    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, dst_ipv4_dst_ipv6.ipv4_layout.ipv4);

    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_sport);
    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport);
    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_sport);
    // MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_dport);

    MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);

    MLX5_SET_CFG(in, start_flow_index, ix);
    ix += MLX5E_FS_CONNTRACK_GROUP1_SIZE;
    MLX5_SET_CFG(in, end_flow_index, ix - 1);

    cht->ft.g[cht->ft.num_groups] = handler(cht->ft.t, in);
    if (!cht->ft.g[0])
        printk("!cht->ft.g[0]\n");

    if (IS_ERR(cht->ft.g[cht->ft.num_groups]))
        goto destroy_groups;

    cht->ft.num_groups++;

    memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5E_FS_CONNTRACK_GROUP2_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	cht->ft.g[cht->ft.num_groups] = handler(cht->ft.t, in);
	if (IS_ERR(cht->ft.g[cht->ft.num_groups]))
		goto destroy_groups;

	cht->ft.num_groups++;

	kvfree(in);
    return 0;

destroy_groups:
	err = PTR_ERR(cht->ft.g[cht->ft.num_groups]);
	cht->ft.g[cht->ft.num_groups] = NULL;
	kvfree(in);

    return err;
}

int add_default_rule(struct mlx5e_conntrack_table *cht)
{
    int err = 0;
    mlx5_add_flow_rules_handler_ptr handler;

    rcu_read_lock();
    handler = rcu_dereference(mlx5_add_flow_rules_handler);
    if (!handler)
    {
        printk("mlx5_create_ft_handler is NULL!\n");
        rcu_read_unlock();
        return -EINVAL;
    }
    rcu_read_unlock();

    MLX5_DECLARE_FLOW_ACT(flow_act);
    flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW;
    flow_act.flags = FLOW_ACT_NO_APPEND;

    cht->default_rule = handler(cht->ft.t, NULL, &flow_act, NULL, 1);
    if (IS_ERR(cht->default_rule))
        return PTR_ERR(cht->default_rule);

    return err;
}

int add_test_rule(struct mlx5e_conntrack_table *cht)
{
    int err = 0;
    struct mlx5_flow_destination dest = {};
    struct mlx5_flow_spec specs = {};
    struct mlx5_flow_spec *spec = NULL;

    u32 src_ip = 0x0A010101;
    // u8 dst_mac[] = {0x50, 0x6b, 0x4b, 0xef, 0xfc, 0x19};


    mlx5_add_flow_rules_handler_ptr handler;

    rcu_read_lock();
    handler = rcu_dereference(mlx5_add_flow_rules_handler);
    if (!handler)
    {
        printk("mlx5_create_ft_handler is NULL!\n");
        rcu_read_unlock();
        return -EINVAL;
    }
    rcu_read_unlock();

    MLX5_DECLARE_FLOW_ACT(flow_act);
    flow_act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR | MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
    flow_act.flags = FLOW_ACT_NO_APPEND;
    flow_act.fg = cht->ft.g[0];

    specs.match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
    spec = &specs;

    void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria, outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value, outer_headers);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ethertype);
    MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype, ETH_P_IP);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_version);
    MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);

    MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, src_ipv4_src_ipv6.ipv4_layout.ipv4);
    memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v, src_ipv4_src_ipv6.ipv4_layout.ipv4), &src_ip, sizeof(src_ip));


    for (int i=0; i<112; i++)
    {
        printk("match_criteria: %u - %u\n", spec->match_criteria[i], cht->ft.g[0]->mask.match_criteria[i]);
    }


    void *modify_actions = kcalloc(1, MLX5_MH_ACT_SZ * 2, GFP_KERNEL);;
    memset(modify_actions, 0, MLX5_MH_ACT_SZ * 2);

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

    flow_act.modify_hdr = mlx5_modify_header_alloc(mlx5e_fs_get_mdev(priv_eth1->fs), MLX5_FLOW_NAMESPACE_KERNEL,
                                              2, modify_actions);
    if (IS_ERR(flow_act.modify_hdr))
    {
        printk("mlx5_modify_header_alloc failed: %ld\n", PTR_ERR(flow_act.modify_hdr));
        return PTR_ERR(flow_act.modify_hdr);
    }

    dest.type = MLX5_FLOW_DESTINATION_TYPE_PORT;
    dest.vport.num = mlx5_core_native_port_num(priv_eth2->mdev);

    printk("mlx5_core_native_port_num:%d\n", mlx5_core_native_port_num(priv_eth1->mdev));
    printk("mlx5_core_native_port_num:%d\n", mlx5_core_native_port_num(priv_eth2->mdev));

    cht->rules[0] = handler(cht->ft.t, spec, &flow_act, &dest, 1);
    if (IS_ERR(cht->rules[0]))
    {
        printk("IS_ERR(cht->rules[0])\n");
        return PTR_ERR(cht->rules[0]);
    }

    cht->num_rules++;
    return err;
}

void del_flow_rules(struct mlx5_flow_handle *h)
{
    mlx5_del_flow_rules_handler_ptr handler;

    rcu_read_lock();
    handler = rcu_dereference(mlx5_del_flow_rules_handler);
    if (!handler)
    {
        printk("mlx5_del_flow_rules_handler is NULL!\n");
        rcu_read_unlock();
        return ;
    }
    rcu_read_unlock();

    handler(h);
    return ;
}

static void destroy_mlx5e_conntrack_table(struct mlx5e_conntrack_table *cht)
{
    del_flow_rules(cht->default_rule);
    for (int i = 0; i < cht->num_rules; i++)
    {
        printk("cht->num_rules:%d i:%d\n", cht->num_rules, i);
        del_flow_rules(cht->rules[i]);
    }

	mlx5e_destroy_flow_table_cp(&cht->ft);

    kfree(cht);
    return ;
}

static int __init conntrack_fastpath_init(void)
{
    int err = 0;

    err = request_module("mlx5_core");
    if (err < 0)
    {
        printk("request module:mlx5_core!\n");
        return err;
    }
    
    err = init_mlx5_priv();
    if (err)
    {
        printk("file:%s line:%d init_mlx5_priv err:%d\n", __FILE__, __LINE__, err);
        return err;
    }

    cht = kcalloc(1, sizeof(struct mlx5e_conntrack_table), GFP_KERNEL);
    if (!cht)
    {
        printk("kcalloc failed!\n");
        return -1;
    }

    err = create_flow_table(cht);
    if (err)
    {
        printk("file:%s line:%d create_flow_table err:%d\n", __FILE__, __LINE__, err);
        return err;
    }

    err = create_table_groups(cht);
    if (err)
    {
        printk("file:%s line:%d create_table_groups err:%d\n", __FILE__, __LINE__, err);
        return err;
    }

    err = add_default_rule(cht);
    if (err)
    {
        printk("file:%s line:%d add_default_rule err:%d\n", __FILE__, __LINE__, err);
        return err;
    }

    err = add_test_rule(cht);
    if (err)
    {
        printk("file:%s line:%d add_test_rule err:%d\n", __FILE__, __LINE__, err);
        destroy_mlx5e_conntrack_table(cht);
        cht = NULL;
        return err;
    }

    return err;
}


static void __exit conntrack_fastpath_exit(void)
{
    destroy_mlx5e_conntrack_table(cht);
    cht = NULL;
    return ;
}


module_init(conntrack_fastpath_init);
module_exit(conntrack_fastpath_exit);

MODULE_LICENSE("GPL");