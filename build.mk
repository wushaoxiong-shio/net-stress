CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86
C_FLAGS     = -g -O2 -lbpf

kernel_version = $(shell uname -r)


INCLUDE_DIR = \
	-I/usr/src/$(kernel_version)/include/ \
	-I/root/code/linux-$(kernel_version)/tools/lib/ \
	-I/root/code/linux-$(kernel_version)/tools/bpf/bpftool/ \

LIBRARY_DIR = \
	-L/root/code/linux-$(kernel_version)/tools/lib/bpf/ \

OUTPUT_DIR = build

BPFTOOL = /root/code/linux-$(kernel_version)/tools/bpf/bpftool/bpftool