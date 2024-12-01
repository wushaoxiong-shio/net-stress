#include "linux/fdtable.h"
#include <linux/module.h>

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>

#include <net/sock.h>
#include <linux/socket.h>

static int __init send_to_socket_init(void)
{
    struct task_struct *task;
    struct files_struct *files;
    struct file *fe;
    struct socket *sock;
    struct sock *sk;

    rcu_read_lock();
    for_each_process(task)
        if (strncmp(task->comm, "create_socket", TASK_COMM_LEN) == 0)
            break;
    
    rcu_read_unlock();

    if (strncmp(task->comm, "create_socket", TASK_COMM_LEN) != 0)
    {
        printk("create_socket not found\n");
        return 0;
    }

    files = task->files;
    printk("task->comm:%s files->next_fd:%d\n", task->comm, files->next_fd);

    for (int i = 0; i < files->next_fd; i++)
    {
        fe = files->fdt->fd[i];
        if (!fe)
        {
            printk("fd:%d file NULL\n", i);
            continue;
        }

        sock = (struct socket *)fe->private_data;
        if (sock && sock->type == SOCK_DGRAM)
        {
            sk = sock->sk;
            printk("fd:%d sock->type: %d, sock: %p\n", i, sock->type, sk);
        }
        else
            printk("sock NULL\n");
    }

	return 0;
}


static void __exit send_to_socket_exit(void)
{
}


module_init(send_to_socket_init);
module_exit(send_to_socket_exit);

MODULE_LICENSE("GPL");