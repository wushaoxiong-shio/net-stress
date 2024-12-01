include ../build.mk

OUTPUT_DIR_TEST = ../$(OUTPUT_DIR)


SUBDIRS_TEST := test
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_TEST)

.PHONY: clean
clean:
	@rm -f *.o *.skel.h


test:
	@clang -c test.bpf.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o test.o
	@gcc test.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_TEST)/test