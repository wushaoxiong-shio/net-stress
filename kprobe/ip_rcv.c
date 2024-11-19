#include "ip_rcv.skel.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


static volatile sig_atomic_t stop;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	stop = 1;
}

void print_ip(__be32 ip)
{
    printf("%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

int main()
{
    struct ip_rcv *skel;
	int err, map_fd;

    libbpf_set_print(libbpf_print_fn);

    skel = ip_rcv__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    err = ip_rcv__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ip_rcv_map");
    if (map_fd < 0)
    {
        perror("Failed to find map by name");
        return -1;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!stop)
    {
		fprintf(stderr, ".");
		usleep(50 * 1000);

        unsigned int value;
        unsigned int key = 0;

        // 读取 map 中的计数值
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
            printf("Packets received via ip_rcv: %d\n", value);
        else
            fprintf(stderr, "Error reading counter from map: %s\n", strerror(errno));

	}

cleanup:
	ip_rcv__destroy(skel);
	return -err;
}