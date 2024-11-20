include ../build.mk

OUTPUT_DIR_KPROBE = ../$(OUTPUT_DIR)


SUBDIRS_KPROBE := tcp_v4_rcv
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_KPROBE)


tcp_v4_rcv:
	@clang $(CLANG_FLAGS) $(INCLUDE_DIR) -c tcp_v4_rcv.bpf.c -o $(OUTPUT_DIR_KPROBE)/tcp_v4_rcv.o
	@$(BPFTOOL) gen skeleton $(OUTPUT_DIR_KPROBE)/tcp_v4_rcv.o > tcp_v4_rcv.skel.h
	@gcc tcp_v4_rcv.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_KPROBE)/tcp_v4_rcv