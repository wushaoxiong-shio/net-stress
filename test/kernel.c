#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


// 定义用于计数的全局映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned int);
} counter_map SEC(".maps");


SEC("kprobe/ip_rcv")
int bpf_test(struct pt_regs *ctx)
{
    unsigned int key = 0;
    unsigned int initial_value = 0;

    // 从映射中读取当前值
    unsigned int *value = bpf_map_lookup_elem(&counter_map, &key);

    if (value) // 增量计数
        __sync_fetch_and_add(value, 1);
    else // 初始化值
        bpf_map_update_elem(&counter_map, &key, &initial_value, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";