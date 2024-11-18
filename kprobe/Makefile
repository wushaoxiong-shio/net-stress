include ../build.mk

OUTPUT_DIR_KPROBE = ../$(OUTPUT_DIR)


SUBDIRS_KPROBE := ip_rcv
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_KPROBE)


ip_rcv:
	@clang $(CLANG_FLAGS) $(INCLUDE_DIR) -c ip_rcv.bpf.c -o $(OUTPUT_DIR_KPROBE)/ip_rcv.o
	@$(BPFTOOL) gen skeleton $(OUTPUT_DIR_KPROBE)/ip_rcv.o > ip_rcv.skel.h
	@gcc ip_rcv.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_KPROBE)/ip_rcv