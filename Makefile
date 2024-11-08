include build.mk


SUBDIRS := test


.PHONY: all
all: $(SUBDIRS)


.PHONY: $(SUBDIRS)
$(SUBDIRS):
	@mkdir -p $(OUTPUT_DIR)
	$(MAKE) -C $@ 

