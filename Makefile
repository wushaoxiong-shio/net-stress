include build.mk


SUBDIRS := test kprobe bcc


.PHONY: all
all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir; done

.PHONY: all
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done
	@rm -r build/*
