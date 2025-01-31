#include "linux/nsproxy.h"
#include "linux/proc_fs.h"
#include "net/net_namespace.h"
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/netfilter.h>

char *nf_inet_hooks_str[NF_INET_NUMHOOKS + 1] = 
{
	"NF_INET_PRE_ROUTING",
	"NF_INET_LOCAL_IN",
	"NF_INET_FORWARD",
	"NF_INET_LOCAL_OUT",
	"NF_INET_POST_ROUTING",
	"NF_INET_NUMHOOKS"
};

struct proc_dir_entry *proc_data = NULL;
struct proc_dir_entry *proc_header = NULL;
struct net *net = NULL;
unsigned int data = 0;


void* seq_start(struct seq_file *m, loff_t *pos)
{
    if (*pos == 0)
        return (void*)1;

    return NULL;
}

void* seq_next(struct seq_file *m, void *v, loff_t *pos)
{
    (*pos) = 1;
    return NULL;
}

void seq_stop(struct seq_file *m, void *v)
{
    return ;
}

int seq_show(struct seq_file *m, void *v)
{
    struct nf_hook_entries *hook_head;
    char buffer[KSYM_SYMBOL_LEN];
    bool empty;

    seq_printf(m, "IPV4:\n");
    for (int n = 0; n < NF_INET_NUMHOOKS; n++)
    {
        hook_head = NULL;
        empty = true;
        seq_printf(m, "-%s\n", nf_inet_hooks_str[n]);
        rcu_read_lock();
        hook_head = rcu_dereference(net->nf.hooks_ipv4[n]);
        if (!hook_head)
            goto skip_v4;

        for (int s = 0; s < hook_head->num_hook_entries; s++)
        {
            empty = false;
            memset(buffer, '\0', KSYM_SYMBOL_LEN);
            sprint_symbol(buffer, (unsigned long)hook_head->hooks[s].hook);
            seq_printf(m, "\t %d - %s\n", s + 1, buffer);
        }
skip_v4:
        rcu_read_unlock();
        if (empty)
            seq_printf(m, "\t (null)\n");

        seq_printf(m, "\n");
    }

    seq_printf(m, "\nIPV6:\n");
    for (int n = 0; n < NF_INET_NUMHOOKS; n++)
    {
        hook_head = NULL;
        empty = true;
        seq_printf(m, "-%s\n", nf_inet_hooks_str[n]);
        rcu_read_lock();
        hook_head = rcu_dereference(net->nf.hooks_ipv6[n]);
        if (!hook_head)
            goto skip_v6;

        for (int s = 0; s < hook_head->num_hook_entries; s++)
        {
            empty = false;
            memset(buffer, '\0', KSYM_SYMBOL_LEN);
            sprint_symbol(buffer, (unsigned long)hook_head->hooks[s].hook);
            seq_printf(m, "\t %d - %s\n", s + 1, buffer);
        }
skip_v6:
        rcu_read_unlock();
        if (empty)
            seq_printf(m, "\t (null)\n");

        seq_printf(m, "\n");
    }

    return 0;
}

static const struct seq_operations seq_ops = {
    .start = seq_start,
    .next  = seq_next,
    .stop  = seq_stop,
    .show  = seq_show
};

int proc_fops_open(struct inode *id, struct file *fe)
{
    seq_open(fe, &seq_ops);
    return 0;
}

const struct proc_ops proc_fops =
{
    .proc_open = proc_fops_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release
};

static int __init filter_hook_init(void)
{
    net = current->nsproxy->net_ns;

    proc_header = proc_net_mkdir(net, "filter_hook", NULL);
    if (!proc_header)
        goto err_mkdir;

    proc_data = proc_create_data("filter_hook", 0644, proc_header, &proc_fops, &data);
    if (!proc_data)
        goto err_create_data;

    return 0;

err_mkdir:
    printk("err_mkdir\n");
    return -1;

err_create_data:
    printk("err_create_data\n");
    remove_proc_subtree("filter_hook", NULL);
    return -2;
}


static void __exit filter_hook_exit(void)
{
    if (proc_data)
        remove_proc_entry("filter_hook", proc_header);

    if (proc_header)
        remove_proc_subtree("filter_hook", NULL);

    return;
}


module_init(filter_hook_init);
module_exit(filter_hook_exit);
MODULE_LICENSE("GPL");