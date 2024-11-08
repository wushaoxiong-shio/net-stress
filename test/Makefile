include ../Makefile


SUBDIRS_TEST := test
.PHONY: $(SUBDIRS_TEST)


.PHONY: all
all: $(SUBDIRS_TEST)
	@mkdir -p $(OUTPUT_DIR)

test:
	clang -c kernel.c $(INCLUDE_DIR) $(CLANG_FLAGS) -o $(OUTPUT_DIR)/kernel.o
	gcc user.c $(INCLUDE_DIR) $(LIBRARY_DIR) $(C_FLAGS) -o $(OUTPUT_DIR)/user