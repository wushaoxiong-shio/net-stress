#include "linux/fdtable.h"
#include "linux/proc_fs.h"
#include "net/netns/generic.h"
#include "net/udp.h"
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/socket.h>


char message[] = "Hello, UDP server!";

unsigned int send_to_socket_net_id = 0;

struct send_to_socket_net
{
    struct net *net;
    struct proc_dir_entry *proc_header;
    unsigned int proc_data;
    struct socket *sock;
    struct sock *sk;
};


int send_msg_to_socket(void)
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
            continue;

        sock = (struct socket *)fe->private_data;
        if (sock && sock->type == SOCK_DGRAM)
            sk = sock->sk;
    }

    if (!sock || sock->type != SOCK_DGRAM || !sk)
    {
        printk("socket not found\n");
        return 1;
    }

    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_in dest_addr;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(55440);
    dest_addr.sin_addr.s_addr = htonl(0x0C0CFED7); 

    iov.iov_base = (void *)message;
    iov.iov_len = strlen(message);

    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);

    iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, iov.iov_len);

    int ret = udp_sendmsg(sk, &msg, strlen(message));
    printk("ret:%d\n", ret);

    return 0;
}


ssize_t proc_data_read(struct file *fe, char *buf, size_t size, loff_t *pos)
{
    if (*pos > 0)
        return 0;

    send_msg_to_socket();

    struct send_to_socket_net *st = net_generic(current->nsproxy->net_ns, send_to_socket_net_id);
    if (!st)
        printk("proc_data_read: net_generic failed\n");

    char data[129];

    *pos += snprintf(data, 128, "___%d___", st->proc_data);

    if (copy_to_user(buf, data, *pos))
        return -EFAULT;

    return *pos;
}


const struct proc_ops proc_data_fops =
{
    .proc_read = proc_data_read
};


int send_to_socket_net_init(struct net *net)
{
    struct proc_dir_entry *proc_data;
    struct send_to_socket_net *st = net_generic(net, send_to_socket_net_id);
    if (!st)
        printk("send_to_socket_net_init: net_generic failed\n");


    st->proc_header = proc_net_mkdir(net, "shio", NULL);
    proc_data = proc_create_data("data", 0644, st->proc_header, &proc_data_fops, &st->proc_data);

    printk("send_to_socket_net_init\n");
    return 0;
}


void send_to_socket_net_exit(struct net *net)
{
    struct send_to_socket_net *st = net_generic(net, send_to_socket_net_id);
    if (!st)
        printk("send_to_socket_net_exit: net_generic failed\n");

    remove_proc_entry("data", st->proc_header);
    remove_proc_subtree("shio", NULL);

    printk("send_to_socket_net_exit\n");
    return ;
}

struct pernet_operations send_to_socket = {
	.init = send_to_socket_net_init,
	.exit = send_to_socket_net_exit,
	.id   = &send_to_socket_net_id,
	.size = sizeof(struct send_to_socket_net)
};


static int __init send_to_socket_init(void)
{
    printk("send_to_socket_init\n");
    register_pernet_subsys(&send_to_socket);

	return 0;
}


static void __exit send_to_socket_exit(void)
{
    unregister_pernet_subsys(&send_to_socket);
    printk("send_to_socket_exit\n");
}


module_init(send_to_socket_init);
module_exit(send_to_socket_exit);

MODULE_LICENSE("GPL");