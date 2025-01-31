
OUTPUT_DIR = ../build
kernel_version = $(shell uname -r)
BPF_TOOLS_DIR=/root/code/linux-$(kernel_version)/tools/bpf/

SUBDIRS_KERNEL_MODULE := filter_hook

.PHONY: all
all: $(SUBDIRS_KERNEL_MODULE)
	
.PHONY: clean
clean:
	@make clean -C /root/code/linux-$(kernel_version)/ M=`pwd`

filter_hook:
	@make -C /root/code/linux-$(kernel_version)/ M=`pwd` 

obj-m += filter_hook.o
