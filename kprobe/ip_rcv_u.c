#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


typedef uint32_t u32;
typedef uint64_t u64;

static volatile int keep_running = 1;

void int_handler(int dummy)
{
    keep_running = 0;
}

void print_ip(__be32 ip)
{
    printf("%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err, map_fd;

    const char *filename = "ip_rcv.o";
    const char *program_name = "bpf_kprobe_ip_rcv";
    const char *func_name = "ip_rcv";

    signal(SIGINT, int_handler);

    // 打开 BPF 对象文件
    obj = bpf_object__open_file(filename, NULL);
    if (!obj)
    {
        fprintf(stderr, "Error: Failed to open BPF object file.\n");
        return 1;
    }

    // 加载所有的 maps 和程序
    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Error: Loading BPF object.\n");
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, program_name);
    if (!prog)
    {
        fprintf(stderr, "Error: Failed to find program.\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_kprobe(prog, false, func_name);
    if (!link)
    {
        perror("Failed to attach kprobe");
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "counter_map");
    if (map_fd < 0)
    {
        perror("Failed to find map by name");
        return -1;
    }

    printf("eBPF program loaded and attached. Reading counters...\n");

    __be32 src_ip, dest_ip;
    __be32 current_key = 0;
    
    while (keep_running && bpf_map_get_next_key(map_fd, &current_key, &src_ip) == 0)
    {
        usleep(100 * 1000);

        // 获取每个 key（源 IP）对应的 value（目标 IP）
        if (bpf_map_lookup_elem(map_fd, &src_ip, &dest_ip) == 0) {
            printf("Source IP: ");
            print_ip(src_ip);
            printf("Destination IP: ");
            print_ip(dest_ip);
        }

        // 更新 current_key 为下一个 key
        current_key = src_ip;
    }

    printf("\nExiting...\n");
    bpf_object__close(obj);
    return 0;
}