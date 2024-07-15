/*
 * lilium-plugin-glib - a plugin to unify programs and libraries (glibc).
 * Copyright (c) 2024 An Van Quoc <andtf2002@gmail.com>
 *
 * This file is part of Lilium Project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>	// For checking directories
#include <libgen.h>	// dirname()
#include <spawn.h>	// posix_spawn()
#include <dlfcn.h>	// dlopen(), dlsym()
#include <sys/socket.h> // netlink socket
#include <linux/netlink.h>
#include "../lilium.h"

#define NETLINK_USER NETLINK_USERSOCK
// https://stackoverflow.com/questions/32898173/can-i-have-more-than-32-netlink-sockets-in-kernelspace
#define NETLINK_GROUP 31
#define MAX_PAYLOAD 16384 /* maximum payload size */

typedef void *(*lm_void_t)();
typedef int (*lm_int_t)();
typedef char *(*lm_charptr_t)();

static char lib_dir[255];
static char bin_dir[255];

static struct sockaddr_nl src_addr;
static struct sockaddr_nl dest_addr;
static struct nlmsghdr *nl_header;
static struct msghdr msg;
static struct iovec iov;
static struct lm_pkt_plugin pkt;
static int sock_fd;
static int rc;

char *concat(const char *s1, const char *s2)
{
	char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
	if (result == NULL)
		return NULL;
	strcpy(result, s1);
	strcat(result, s2);
	return result;
}

/* Send pkt to Lilium kernel module */
int send_to_module()
{
	// Allocate header
	nl_header = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

	/* Fill the netlink message header */
	nl_header->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nl_header->nlmsg_pid = getpid();
	nl_header->nlmsg_flags = 0;

	/* Fill in the netlink message payload */
	memcpy(NLMSG_DATA(nl_header), &pkt, sizeof(pkt));

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (void *)nl_header;
	iov.iov_len = nl_header->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Send to kernel: %p, opcode: %i\n", &msg, pkt.opcode);

	rc = sendmsg(sock_fd, &msg, 0);
	if (rc < 0)
	{
		printf("Sendmsg failed: %s\n", strerror(errno));
	}
	else
	{
		printf("Sendmsg success: %p\n", &msg);
	}
}

void read_event(int sock)
{
	struct sockaddr_nl nl_recv_addr;
	struct msghdr recv_msg;
	struct iovec recv_iov;
	char buffer[65536];
	int ret;

	recv_iov.iov_base = (void *)buffer;
	recv_iov.iov_len = sizeof(buffer);
	recv_msg.msg_name = (void *)&(nl_recv_addr);
	recv_msg.msg_namelen = sizeof(nl_recv_addr);
	recv_msg.msg_iov = &recv_iov;
	recv_msg.msg_iovlen = 1;

	ret = recvmsg(sock, &recv_msg, 0);
	if (ret < 0)
		return; // No message yet, probably -EAGAIN

	struct lm_pkt_module *recv_payload = NLMSG_DATA((struct nlmsghdr *)&buffer);
	printf("Received from kernel: %p, opcode %i\n", recv_payload, recv_payload->opcode);

	// do something with the packet
	switch (recv_payload->opcode)
	{
	case LILIUM_PING_OPCODE:
	{
		// send back the data
		pkt = (struct lm_pkt_plugin){
		    .opcode = LILIUM_PING_OPCODE,
		    .data = "",
		};
		send_to_module();
		break;
	}

	case LILIUM_EXEC_OPCODE:
	{
		struct lm_exec_data exec_data = *((struct lm_exec_data *)(recv_payload->data));

		char merged[128];
		memset(merged, '\0', sizeof(merged));
		strcat(merged, bin_dir);
		strcat(merged, exec_data.sym);
		strcat(merged, "-");
		strcat(merged, exec_data.ver);
		pid_t lm_e_pid;

		char *exec_data_argv[5];
		strncpy(exec_data.argv[0], merged, sizeof(exec_data.argv[0]));
		for (int i = 0; i < 5; i++)
		{
			exec_data_argv[i] = exec_data.argv[i];
		}
		char *exec_data_envp[5];
		for (int i = 0; i < 5; i++)
		{
			exec_data_envp[i] = exec_data.envp[i];
		}

		printf("Now executing: %s\n", exec_data_argv[0]);

		pkt = (struct lm_pkt_plugin){
		    .opcode = LILIUM_EXEC_OPCODE,
		};

		int lm_e_result = -posix_spawn(&lm_e_pid, merged, NULL, NULL, exec_data_argv, exec_data_envp);
		if (lm_e_result != 0)
		{
			printf("Cannot execute %s: %s\n", exec_data_argv[0], strerror(errno));
			memcpy(&pkt.data, &lm_e_result, sizeof(pid_t));
			send_to_module();
		}
		else
		{
			memcpy(&pkt.data, &lm_e_pid, sizeof(pid_t));
			send_to_module();
		}
		break;
	}

	case LILIUM_FUN_OPCODE:
	{
		struct lm_fun_data fun_data = *((struct lm_fun_data *)(recv_payload->data));

		char fun_merged[128];
		memset(fun_merged, '\0', sizeof(fun_merged));
		strcat(fun_merged, lib_dir);
		strcat(fun_merged, fun_data.sym);
		strcat(fun_merged, "-");
		strcat(fun_merged, fun_data.ver);
		strcat(fun_merged, ".so");

		printf("Now loading library: %s\n", fun_merged);

		void *dl_hdl = dlopen(fun_merged, RTLD_NOW | RTLD_GLOBAL);
		if (!dl_hdl)
		{
			pkt = (struct lm_pkt_plugin){
			    .opcode = LILIUM_FUN_OPCODE,
			    .data = ""};
			printf("Cannot open library: %s\n", dlerror());
			send_to_module();
			return;
		}

		printf("Now running function: %s, type: %u, from: %p\n", fun_data.name, fun_data.ret_type, dl_hdl);
		// Check null on fun_data

		pkt = (struct lm_pkt_plugin){
		    .opcode = LILIUM_FUN_OPCODE,
		};

		switch (fun_data.ret_type)
		{
		case LILIUM_FUN_RET_VOID:
		{
			lm_void_t lm_fun_void_hdl = (lm_void_t)dlsym(dl_hdl, fun_data.name);
			switch (fun_data.input_size)
			{
			case 0:
			{
				lm_fun_void_hdl();
				break;
			}

			case 1:
			{
				lm_fun_void_hdl(fun_data.argv[0]);
				break;
			}

			case 2:
			{
				lm_fun_void_hdl(fun_data.argv[0], fun_data.argv[1]);
				break;
			}

			default:
				printf("Invalid / Unsupported number of arguments: %u\n", fun_data.input_size);
				break;
			}

			strcpy(&(pkt.data[0]), "1");
		}

		case LILIUM_FUN_RET_INT:
		{
			lm_int_t lm_fun_int_hdl = (lm_int_t)dlsym(dl_hdl, fun_data.name);
			int lm_fun_int_result;
			switch (fun_data.input_size)
			{
			case 0:
			{
				lm_fun_int_result = lm_fun_int_hdl();
				break;
			}
			case 1:
			{
				char arg1[strlen(fun_data.argv[0])];
				memcpy(arg1, fun_data.argv[0], strlen(fun_data.argv[0]));
				lm_fun_int_result = lm_fun_int_hdl(fun_data.argv[0]);
				break;
			}
			case 2:
			{
				char arg1[strlen(fun_data.argv[0])];
				memcpy(arg1, fun_data.argv[0], strlen(fun_data.argv[0]));
				char arg2[strlen(fun_data.argv[1])];
				memcpy(arg2, fun_data.argv[1], strlen(fun_data.argv[1]));
				lm_fun_int_result = lm_fun_int_hdl(*arg1, *arg2);
				break;
			}
			}

			memcpy(pkt.data, &lm_fun_int_result, sizeof(lm_fun_int_result));
			break;
		}

		case LILIUM_FUN_RET_CHARPTR:
		{
			lm_charptr_t lm_fun_charptr_hdl = (lm_charptr_t)dlsym(dl_hdl, fun_data.name);
			char lm_fun_charptr_result[LILIUM_MAX_SIZE];
			switch (fun_data.input_size)
			{
			case 0:
			{
				strcpy(lm_fun_charptr_result, lm_fun_charptr_hdl());
				break;
			}
			case 1:
			{
				char arg1[strlen(fun_data.argv[0])];
				memcpy(arg1, fun_data.argv[0], strlen(fun_data.argv[0]));
				strcpy(lm_fun_charptr_result, lm_fun_charptr_hdl(fun_data.argv[0]));
				break;
			}
			case 2:
			{
				char arg1[strlen(fun_data.argv[0])];
				memcpy(arg1, fun_data.argv[0], strlen(fun_data.argv[0]));
				char arg2[strlen(fun_data.argv[1])];
				memcpy(arg2, fun_data.argv[1], strlen(fun_data.argv[1]));
				strcpy(lm_fun_charptr_result, lm_fun_charptr_hdl(fun_data.argv[0], fun_data.argv[1]));
				break;
			}
			}

			memcpy(pkt.data, lm_fun_charptr_result, sizeof(lm_fun_charptr_result));
			break;
		}

		default:
		{
			printf("Invalid / Unsupported return value %u", fun_data.ret_type);
			return;
		}
		}

		send_to_module();
		break;
	}

	default:
	{
		printf("Invalid opcode %i, not processing.\n", recv_payload->opcode);
		send_to_module();
		break;
	}
	}
}

void handle_sigint(int signo)
{
	if (signo == SIGINT)
	{
		printf("\nClosing socket, goodbye...\n");
		close(sock_fd);
		exit(0);
	}
}

int main(int argc, char **argv)
{
	// check param
	if (argc != 3)
	{
		printf("Invalid arguments!\n");
		printf("Usage: ./plugin <binary_path> <library_path>\n");
		return 1;
	}

	DIR *dir_tester;
	dir_tester = opendir(argv[1]);
	if (!dir_tester)
	{
		printf("Cannot open binary path \"%s\": %s\n", argv[1], strerror(errno));
		return 1;
	}
	else
	{
		strncpy(bin_dir, argv[1], strlen(argv[1]));
		printf("Set binary path: %s\n", bin_dir);
	}

	dir_tester = opendir(argv[2]);
	if (!dir_tester)
	{
		printf("Cannot open library path \"%s\"%s: %s\n", argv[2], strerror(errno));
		return 1;
	}
	else
	{
		strncpy(lib_dir, argv[2], strlen(argv[2]));
		printf("Set library path: %s\n", lib_dir);
	}

	closedir(dir_tester);

	// create socket
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (sock_fd < 0)
	{
		printf("socket(): %s\n", strerror(errno));
		return 1;
	}

	// handle sigint
	if (signal(SIGINT, handle_sigint) == SIG_ERR)
	{
		printf("signal(): cannot catch sigint");
		return 1;
	}

	// From user...
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	// src_addr.nl_groups = 0;
	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	// ..to module
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */

	int group = NETLINK_GROUP;
	if (setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0)
	{
		printf("setsockopt: %s\n", strerror(errno));
		return 1;
	}

	printf("Ready to accept connection from module.\n");

	while (1)
	{
		read_event(sock_fd);
	}

	return 0;
}