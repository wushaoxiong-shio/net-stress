include ../Makefile



SUBDIRS_TEST := test
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_TEST)


test:
	clang -c kernel.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o kernel.o
	gcc user.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o user