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

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err, map_fd;

    const char *filename = "test/test.o";
    const char *program_name = "bpf_test";
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

    while (keep_running)
    {
        usleep(100 * 1000);

        u64 value;
        u32 key = 0;

        // 读取 map 中的计数值
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
            printf("Packets received via ip_rcv: %lu\n", value);
        else
            fprintf(stderr, "Error reading counter from map: %s\n", strerror(errno));
    }

    printf("\nExiting...\n");
    bpf_object__close(obj);
    return 0;
}