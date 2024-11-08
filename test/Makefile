include ../build.mk

OUTPUT_DIR_TEST = ../$(OUTPUT_DIR)


SUBDIRS_TEST := test
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_TEST)


test:
	@clang -c kernel.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o $(OUTPUT_DIR_TEST)/kernel.o
	@gcc user.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR_TEST)/user