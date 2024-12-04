include build.mk


SUBDIRS := test kernel_module bcc


.PHONY: all
all:
	@mkdir -p $(OUTPUT_DIR)
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir; done

.PHONY: clean
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done
	@rm -rf $(OUTPUT_DIR)
