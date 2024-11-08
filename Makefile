include build.mk


SUBDIRS := test kprobe


.PHONY: all
all: $(SUBDIRS)


.PHONY: $(SUBDIRS)
$(SUBDIRS):
	@mkdir -p $(OUTPUT_DIR)
	@$(MAKE) -C $@ 

