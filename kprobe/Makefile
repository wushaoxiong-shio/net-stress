include ../build.mk

OUTPUT_DIR_KPROBE = ../$(OUTPUT_DIR)


SUBDIRS_KPROBE := ip_rcv
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_KPROBE)


ip_rcv:
	clang -c ip_rcv_k.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o $(OUTPUT_DIR_KPROBE)/ip_rcv.o
	gcc ip_rcv_u.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_KPROBE)/ip_rcv