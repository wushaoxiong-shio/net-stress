include ../build.mk

OUTPUT_DIR_KPROBE = ../$(OUTPUT_DIR)


SUBDIRS_KPROBE := hello_world
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_KPROBE)

.PHONY: clean
clean:
	@rm -f *.o *.skel.h

hello_world:
	@clang $(CLANG_FLAGS) $(INCLUDE_DIR) -c hello_world.bpf.c -o hello_world.o
	@$(BPFTOOL) gen skeleton hello_world.o > hello_world.skel.h
	@gcc hello_world.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_KPROBE)/hello_world