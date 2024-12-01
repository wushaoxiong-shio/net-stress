
OUTPUT_DIR = ../build
kernel_version = $(shell uname -r)
BPF_TOOLS_DIR=/root/code/linux-$(kernel_version)/tools/bpf/

SUBDIRS_KERNEL_MODULE := kernel_module create_socket

.PHONY: all
all: $(SUBDIRS_KERNEL_MODULE)
	
.PHONY: clean
clean:
	@make clean -C /root/code/linux-$(kernel_version)/ M=`pwd`

kernel_module:
	@make -C /root/code/linux-$(kernel_version)/ M=`pwd` 


obj-m += send_to_socket_kernel.o
create_socket:
	@g++ create_socket.cc -o $(OUTPUT_DIR)/create_socket

