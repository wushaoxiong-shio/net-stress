include ../build.mk

OUTPUT_DIR_TEST = ../$(OUTPUT_DIR)

SUBDIRS_TEST := test tcp_v4_rcv


.PHONY: all
all: $(SUBDIRS_TEST)

.PHONY: clean
clean:
	@rm -f *.o *.skel.h

tcp_v4_rcv:
	@clang $(CLANG_FLAGS) $(INCLUDE_DIR) -c tcp_v4_rcv.bpf.c -o tcp_v4_rcv.o
	@$(BPFTOOL) gen skeleton tcp_v4_rcv.o > tcp_v4_rcv.skel.h
	@gcc tcp_v4_rcv.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_TEST)/tcp_v4_rcv

test:
	@clang -c test.bpf.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o test.o
	@gcc test.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_TEST)/test