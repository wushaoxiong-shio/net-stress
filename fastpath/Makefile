include ../build.mk

OUTPUT_DIR_TEST = ../$(OUTPUT_DIR)

SUBDIRS_TEST := xdp_fastpath

.PHONY: all
all: $(SUBDIRS_TEST)

.PHONY: clean
clean:
	@rm -f *.o *.skel.h

xdp_fastpath:
	clang $(CLANG_FLAGS) $(INCLUDE_DIR) -c xdp_fastpath.bpf.c -o xdp_fastpath.bpf.o
