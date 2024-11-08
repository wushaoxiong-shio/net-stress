CLANG_FLAGS = -O2 -g -target bpf
C_FLAGS     = -O2 -g -lbpf

INCLUDE_DIR = \
	-I/usr/src/6.1.115/include/ \
	-I/root/code/linux-6.1.115/tools/bpf/ \
	-I/root/code/linux-6.1.115/tools/lib/ \

LIBRARY_DIR = \
	-L/root/code/linux-6.1.115/tools/lib/bpf/ \

OUTPUT_DIR = build

SUBDIRS := test


.PHONY: all
all: $(SUBDIRS)

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ 

