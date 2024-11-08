CLANG_FLAGS = -O2 -g -target bpf
C_FLAGS     = -O2 -g -lbpf

kernel_version = 6.1.115


INCLUDE_DIR = \
	-I/usr/src/$(kernel_version)/include/ \
	-I/root/code/linux-$(kernel_version)/tools/bpf/ \
	-I/root/code/linux-$(kernel_version)/tools/lib/ \

LIBRARY_DIR = \
	-L/root/code/linux-$(kernel_version)/tools/lib/bpf/ \

OUTPUT_DIR = build

