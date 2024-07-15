// SPDX-License-Identifier: GPL-2.0

/*
 * lilium - a project to unify programs and libraries (kernel module).
 * Copyright (c) 2024 An Van Quoc <andtf2002@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kdev_t.h>  // types definition for kernel devices
#include <linux/cdev.h>	   // charater file for ioctl
#include <linux/device.h>  // device file for ioctl
#include <linux/slab.h>	   // kmalloc()
#include <linux/uaccess.h> // permissions
#include <linux/ioctl.h>
#include <linux/err.h> // errno
#include <linux/init.h>
#include <linux/jiffies.h> // frequencies for completion
#include <linux/fs.h>	   // inodes
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/version.h>
#include <linux/errname.h> // errname()
#include <linux/errno.h>
#include <linux/completion.h>
#include <net/sock.h> // for netlink socket init
#include "lilium.h"

/*
 * MISC VARIABLES
 */

// Me lilium-likey module name
#define LILIUM_NAME THIS_MODULE->name
#define LILIUM_DEFAULT_TIMEOUT 30000
#define SUCCESS 0

static atomic_t lm_busy = ATOMIC_INIT(0); /* Busy flag, ensuring return value are flushed before any further task */
static struct completion lm_progress;	  /* Monitor for completion when processing */
static struct lm_pkt_user lm_user;	  /* Input value from userspace programs */
static struct lm_pkt_plugin lm_output;	  /* Output value from plugin */

/*
 * NETLINK DEFINITIONS
 */
#define NETLINK_UNIT NETLINK_USERSOCK
#define NETLINK_GROUP 31
static struct sock *nl_sock = NULL;

/* Function when the netlink socket received the payload */
static void nl_recv(struct sk_buff *buff)
{
	struct nlmsghdr *nl_header;
	int pid;
	int opcode;

	nl_header = (struct nlmsghdr *)buff->data;
	pid = nl_header->nlmsg_pid;
	lm_output = *(struct lm_pkt_plugin *)nlmsg_data(nl_header);
	opcode = lm_output.opcode;

	// Report the opcode
	pr_info("%s - %s: Received netlink packet from %i, opcode %i\n", LILIUM_NAME, __FUNCTION__, pid, opcode);

	// Now process the data according to the opcode
	switch (opcode)
	{
	case LILIUM_RECEIVE_OPCODE:
		break;
	case LILIUM_PING_OPCODE:
		pr_info("%s - %s: Ping acknowledged.\n", LILIUM_NAME, __FUNCTION__);
		complete(&lm_progress);
		break;
	case LILIUM_EXEC_OPCODE:
		pr_info("%s - %s: Received result from process call.\n", LILIUM_NAME, __FUNCTION__);
		complete(&lm_progress);
		break;
	case LILIUM_FUN_OPCODE:
		pr_info("%s - %s: Received result from function call.\n", LILIUM_NAME, __FUNCTION__);
		complete(&lm_progress);
		break;
	default:
		pr_warn("%s - %s: Invalid opcode: %i", LILIUM_NAME, __FUNCTION__, opcode);
		break;
	}
}

/*
 * IOCTL DEFINITIONS
 */
#define IOCTL_MAGIC 'a'	    /* https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-number.html */
#define IOCTL_NAME "lilium" /* /dev/lilium */
#define WR_LM_PING _IOWR(IOCTL_MAGIC, '1', unsigned long)
#define WR_LM_EXEC _IOWR(IOCTL_MAGIC, '2', unsigned long)
#define WR_LM_FUN _IOWR(IOCTL_MAGIC, '3', unsigned long)

static dev_t dev = 0;
static struct class *dev_class;
static struct cdev ioctl_cdev;

static int open_ioctl(struct inode *inode, struct file *file)
{
	pr_info("%s: IOCTL opened.", LILIUM_NAME);
	return 0;
}
static int release_ioctl(struct inode *inode, struct file *file)
{
	pr_info("%s: IOCTL released.", LILIUM_NAME);
	return 0;
}
static long process_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (atomic_read(&lm_busy))
	{
		return -EAGAIN;
	}
	else
	{
		atomic_cmpxchg(&lm_busy, 0, 1);
	}

	void __user *arg_user = (void __user *)arg;
	if (copy_from_user(&lm_user, arg_user, sizeof(struct lm_pkt_user)))
	{
		pr_err("%s - %s (%i): Cannot write input from user to module", LILIUM_NAME, __FUNCTION__, LILIUM_PING_OPCODE);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return -EPERM;
	}
	else
	{
		switch (cmd)
		{
		case WR_LM_PING:
		{
			unsigned int time = *((unsigned int *)lm_user.input);
			int lm_ping_result = lm_ping(time);
			*((int *)lm_user.output) = lm_ping_result;
			if (copy_to_user(arg_user, &lm_user, sizeof(struct lm_pkt_user)))
			{
				pr_err("%s - %s (%i): Cannot write input from module to user", LILIUM_NAME, __FUNCTION__, LILIUM_PING_OPCODE);
			}
			else
			{
				int lm_ping_pr = *(int *)(((struct lm_pkt_user __user *)arg)->output);
				pr_info("%s - %s (%i): Send to userspace: %i", LILIUM_NAME, __FUNCTION__, LILIUM_PING_OPCODE, lm_ping_pr);
			}
			break;
		}

		case WR_LM_EXEC:
		{
			struct lm_exec_data lm_e_data;
			memcpy(&lm_e_data, lm_user.input, sizeof(struct lm_exec_data));
			pid_t lm_exec_result = lm_exec(lm_e_data);
			*((pid_t *)lm_user.output) = lm_exec_result;

			if (copy_to_user(arg_user, &lm_user, sizeof(struct lm_pkt_user)))
			{
				pr_err("%s - %s (%i): Cannot write input from module to user", LILIUM_NAME, __FUNCTION__, LILIUM_EXEC_OPCODE);
			}
			else
			{
				pid_t lm_exec_pr = *(pid_t *)(((struct lm_pkt_user __user *)arg)->output);
				pr_info("%s - %s (%i): Send to userspace: %i", LILIUM_NAME, __FUNCTION__, LILIUM_EXEC_OPCODE, lm_exec_pr);
			}
			break;
		}

		case WR_LM_FUN:
		{
			struct lm_fun_data lm_fn_data;
			memcpy(&lm_fn_data, lm_user.input, sizeof(struct lm_fun_data));
			struct lm_ret lm_fun_result = lm_fun(lm_fn_data);
			char lm_fun_result_serial[sizeof(struct lm_ret)];
			memcpy(lm_fun_result_serial, &lm_fun_result, sizeof(struct lm_ret));
			*((char *)lm_user.output) = *lm_fun_result_serial;

			if (copy_to_user(arg_user, &lm_user, sizeof(struct lm_pkt_user)))
			{
				pr_err("%s - %s (%i): Cannot write input from module to user", LILIUM_NAME, __FUNCTION__, LILIUM_FUN_OPCODE);
			}
			else
			{
				pr_info("%s - %s (%i): Send to userspace <data, %lu bytes>", LILIUM_NAME, __FUNCTION__, LILIUM_FUN_OPCODE, strlen(lm_user.output) * sizeof(char));
			}
			break;
		}

		default:
			pr_err("%s - %s: Invalid opcode: %i", LILIUM_NAME, __FUNCTION__, cmd);
			atomic_cmpxchg(&lm_busy, 1, 0);
			break;
		}
	}

	// Flush the lm_user
	return SUCCESS;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open_ioctl,
    .release = release_ioctl,
    .unlocked_ioctl = process_ioctl,
};

/*
 * MISC FUNCTIONS
 */

static struct lm_pkt_plugin get_pkt_output(void)
{
	struct lm_pkt_plugin temp = lm_output;
	memset(&lm_output, 0, sizeof(lm_output));
	return temp;
};

/*
 * MODULE API
 */
int lm_ping(unsigned int time)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_header;
	struct lm_pkt_module pkt = {
	    .opcode = LILIUM_PING_OPCODE,
	    .data = "PING",
	};
	int pkt_size = sizeof(struct lm_pkt_plugin);
	int nl_result = 0;
	unsigned long comp_result = 0;

	// Create a reply
	skb_out = nlmsg_new(pkt_size, 0);
	if (!skb_out)
	{
		pr_err("%s - %s: Failed to allocate socket buffer\n", LILIUM_NAME, __FUNCTION__);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return -ENOMEM;
	}

	// Add the message content to socket buffer
	nl_header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, pkt_size, 0);
	// NETLINK_CB(skb_out).dst_group = 0;  // This is for unicast
	memcpy(nlmsg_data(nl_header), &pkt, pkt_size);

	pr_info("%s - %s: Sending payload, opcode %i\n", LILIUM_NAME, __FUNCTION__, pkt.opcode);

	nl_result = nlmsg_multicast(nl_sock, skb_out, 0, NETLINK_GROUP, GFP_KERNEL);
	if (nl_result < 0)
	{
		pr_warn("%s - %s: Cannot broadcast message: %s", LILIUM_NAME, __FUNCTION__, errname(nl_result));
		atomic_cmpxchg(&lm_busy, 1, 0);
		return nl_result;
	}

	comp_result = wait_for_completion_timeout(&lm_progress, msecs_to_jiffies(time));
	if (!comp_result)
	{
		pr_warn("%s - %s: Cannot connect to plugin: Connection timed out", LILIUM_NAME, __FUNCTION__);
		memset(&lm_output, 0, sizeof(lm_output));
		reinit_completion(&lm_progress);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return -ETIMEDOUT;
	}

	get_pkt_output();
	reinit_completion(&lm_progress);
	atomic_cmpxchg(&lm_busy, 1, 0); // Now idle

	return SUCCESS;
}

int lm_register(void)
{
	return -EPERM;
}

int lm_unregister(void)
{
	return -EPERM;
}

pid_t lm_exec(struct lm_exec_data data)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_header;

	// char data_as_char[LILIUM_MAX_SIZE];
	// struct lm_exec_data *temp_exec_data = (struct lm_exec_data *)((void *)data_as_char);

	// memcpy(temp_exec_data->sym, &(data.sym[0]), sizeof(data.sym) * sizeof(char));
	// memcpy(temp_exec_data->ver, &(data.ver[0]), sizeof(data.ver) * sizeof(char));
	// memcpy(temp_exec_data->argv, &(data.argv[0]), sizeof(data.argv) * sizeof(char));
	// memcpy(temp_exec_data->envp, &(data.envp[0]), sizeof(data.envp) * sizeof(char));

	struct lm_pkt_module pkt = {
	    .opcode = LILIUM_EXEC_OPCODE,
	};
	memcpy(pkt.data, &data, sizeof(struct lm_exec_data));

	int pkt_size = sizeof(struct lm_pkt_plugin);
	int nl_result = 0;
	unsigned long comp_result = 0;

	// Create a reply
	skb_out = nlmsg_new(pkt_size, 0);
	if (!skb_out)
	{
		pr_err("%s - %s: Failed to allocate socket buffer\n", LILIUM_NAME, __FUNCTION__);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return -ENOMEM;
	}

	// Add the message content to socket buffer
	nl_header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, pkt_size, 0);
	// NETLINK_CB(skb_out).dst_group = 0;  // This is for unicastemp_exec_data->
	memcpy(nlmsg_data(nl_header), &pkt, pkt_size);

	pr_info("%s - %s: Sending payload, opcode %i\n", LILIUM_NAME, __FUNCTION__, pkt.opcode);

	nl_result = nlmsg_multicast(nl_sock, skb_out, 0, NETLINK_GROUP, GFP_KERNEL);
	if (nl_result < 0)
	{
		pr_warn("%s - %s: Cannot broadcast message: %s", LILIUM_NAME, __FUNCTION__, errname(nl_result));
		atomic_cmpxchg(&lm_busy, 1, 0);
		return nl_result;
	}

	comp_result = wait_for_completion_timeout(&lm_progress, msecs_to_jiffies(LILIUM_DEFAULT_TIMEOUT));
	if (!comp_result)
	{
		pr_warn("%s - %s: Cannot connect to plugin: Connection timed out", LILIUM_NAME, __FUNCTION__);
		memset(&lm_output, 0, sizeof(lm_output));
		reinit_completion(&lm_progress);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return -ETIMEDOUT;
	}

	pid_t pid = *((pid_t *)get_pkt_output().data);
	reinit_completion(&lm_progress);
	atomic_cmpxchg(&lm_busy, 1, 0); // Now idle

	return pid;
}

struct lm_ret lm_fun(struct lm_fun_data data)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_header;
	
	struct lm_pkt_module pkt = {
	    .opcode = LILIUM_FUN_OPCODE,
	    .data = "",
	};
	memcpy(pkt.data, &data, sizeof(struct lm_fun_data));

	int pkt_size = sizeof(struct lm_pkt_plugin);
	int nl_result = 0;
	unsigned long comp_result = 0;

	// Create a reply
	skb_out = nlmsg_new(pkt_size, 0);
	if (!skb_out)
	{
		pr_err("%s - %s: Failed to allocate socket buffer\n", LILIUM_NAME, __FUNCTION__);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return (struct lm_ret){
		    .val = ""};
	}

	// Add the message content to socket buffer
	nl_header = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, pkt_size, 0);
	// NETLINK_CB(skb_out).dst_group = 0;  // This is for unicast
	memcpy(nlmsg_data(nl_header), &pkt, pkt_size);

	pr_info("%s - %s: Sending payload, opcode %i\n", LILIUM_NAME, __FUNCTION__, pkt.opcode);

	nl_result = nlmsg_multicast(nl_sock, skb_out, 0, NETLINK_GROUP, GFP_KERNEL);
	if (nl_result < 0)
	{
		pr_warn("%s - %s: Cannot broadcast message: %s", LILIUM_NAME, __FUNCTION__, errname(nl_result));
		atomic_cmpxchg(&lm_busy, 1, 0);
		return (struct lm_ret){
		    .val = ""};
	}

	comp_result = wait_for_completion_timeout(&lm_progress, msecs_to_jiffies(LILIUM_DEFAULT_TIMEOUT));
	if (!comp_result)
	{
		pr_warn("%s - %s: Cannot connect to plugin: Connection timed out", LILIUM_NAME, __FUNCTION__);
		memset(&lm_output, 0, sizeof(lm_output));
		reinit_completion(&lm_progress);
		atomic_cmpxchg(&lm_busy, 1, 0);
		return (struct lm_ret){
		    .val = ""};
	}

	struct lm_ret retval;
	strncpy(retval.val, get_pkt_output().data, LILIUM_MAX_SIZE);
	reinit_completion(&lm_progress);
	atomic_cmpxchg(&lm_busy, 1, 0); // Now idle

	return retval;
}

static int __init lm_init(void)
{
	pr_info("%s: Starting.\n", LILIUM_NAME);

	// Init completion
	init_completion(&lm_progress);

	// Init netlink
	struct netlink_kernel_cfg cfg = {
	    .input = nl_recv,
	};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
	nl_sock = netlink_kernel_create(&init_net, NETLINK_UNIT, 0, nl_recv_msg, NULL, THIS_MODULE);
#else
	nl_sock = netlink_kernel_create(&init_net, NETLINK_UNIT, &cfg);
#endif

	if (!nl_sock)
	{
		pr_alert("%s: Error creating socket.\n", LILIUM_NAME);
		return -EPERM;
	}

	pr_info("%s: Netlink connection established.\n", LILIUM_NAME);

	// Init ioctl
	if ((alloc_chrdev_region(&dev, 0, 1, IOCTL_NAME)) < 0)
	{
		pr_err("%s: Cannot allocate major number\n", LILIUM_NAME);
		return -ENOMEM;
	}
	pr_info("%s: Register chrdev success, ma = %i, mi = %i\n", LILIUM_NAME, MAJOR(dev), MINOR(dev));

	/* Creating charater device structure */
	cdev_init(&ioctl_cdev, &fops);

	/* Adding character device to the system */
	if ((cdev_add(&ioctl_cdev, dev, 1)) < 0)
	{
		pr_err("%s: Cannot add charater device\n", LILIUM_NAME);
		goto fail_class;
	}

	/* Creating struct class */
	if (IS_ERR(dev_class = class_create("lilium")))
	{
		pr_err("%s: Cannot create struct class\n", LILIUM_NAME);
		goto fail_class;
	}

	/* Creating device */
	if (IS_ERR(device_create(dev_class, NULL, dev, NULL, "lilium")))
	{
		pr_err("%s: Cannot create device class\n", LILIUM_NAME);
		goto fail_device;
	}

	pr_info("%s: Ready to handle connections.", LILIUM_NAME);

	return SUCCESS;

fail_device:
	class_destroy(dev_class);
fail_class:
	unregister_chrdev_region(dev, 1);

	return -ENOMEM;
}

static void __exit lm_exit(void)
{
	pr_info("%s: Closing.", LILIUM_NAME);
	device_destroy(dev_class, dev);
	class_destroy(dev_class);
	cdev_del(&ioctl_cdev);
	unregister_chrdev_region(dev, 1);
	netlink_kernel_release(nl_sock);
	pr_info("%s: Finished flushing, goodbye.", LILIUM_NAME);
}

EXPORT_SYMBOL(lm_ping);
EXPORT_SYMBOL(lm_register);
EXPORT_SYMBOL(lm_unregister);
EXPORT_SYMBOL(lm_exec);
EXPORT_SYMBOL(lm_fun);

module_init(lm_init);
module_exit(lm_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0-devel");
MODULE_AUTHOR("An Van Quoc <andtf2002@gmail.com>");
MODULE_DESCRIPTION("A project to unify programs and libraries");