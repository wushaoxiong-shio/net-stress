#ifndef __MLX5_FASTPATH_H__
#define __MLX5_FASTPATH_H__

#include "en/fs.h"
#include "fs_core.h"

#define MLX5E_FS_CONNTRACK_NUM_GROUPS	 (2)
#define MLX5E_FS_CONNTRACK_GROUP1_SIZE	 (BIT(16))
#define MLX5E_FS_CONNTRACK_GROUP2_SIZE	 (BIT(0))
#define MLX5E_FS_CONNTRACK_TABLE_SIZE    (MLX5E_FS_CONNTRACK_GROUP1_SIZE + MLX5E_FS_CONNTRACK_GROUP2_SIZE)

enum table_type
{
    IPV4_UDP_TYPE,
    IPV4_TCP_TYPE,
    IPV6_UDP_TYPE,
    IPV6_TCP_TYPE
};

struct mlx5e_conntrack_table {
    enum table_type table_name;
	struct mlx5e_flow_table ft;
    struct mlx5_flow_namespace *ns;
    struct mlx5_flow_table_attr ft_attr;
    struct mlx5_flow_handle *default_rule;
    unsigned int num_rules;
    struct mlx5_flow_handle *rules[2];
};





#endif