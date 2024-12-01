#include <linux/module.h>





static int __init send_to_socket_init(void)
{
    
	return 0;
}


static void __exit send_to_socket_exit(void)
{
	;
}


module_init(send_to_socket_init);
module_exit(send_to_socket_exit);

MODULE_LICENSE("GPL");