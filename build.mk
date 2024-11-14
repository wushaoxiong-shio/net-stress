CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_X86
C_FLAGS     = -g -O2 -lbpf

kernel_version = 6.1.115


INCLUDE_DIR = \
	-I/usr/src/$(kernel_version)/include/ \
	-I/root/code/linux-$(kernel_version)/tools/lib/ \
	-I/root/code/linux-$(kernel_version)/tools/bpf/bpftool/ \

LIBRARY_DIR = \
	-L/root/code/linux-$(kernel_version)/tools/lib/bpf/ \

OUTPUT_DIR = build

