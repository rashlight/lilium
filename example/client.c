/*
 * Copyright (c) 2024 An Van Quoc <andtf2002@gmail.com>
 *
 * This file is part of Lilium Project.
 *
 * You can redistribute this file unders the terms of the MIT license,
 * see LICENSE-MIT file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // Linux-specific types
#include <sys/stat.h> // pid_t, etc.
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h> // IOCTL
#include "../lilium.h"

#define IOCTL_MAGIC 'a' /* https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-number.html */
#define WR_LM_PING _IOWR(IOCTL_MAGIC, '1', unsigned long)
#define WR_LM_EXEC _IOWR(IOCTL_MAGIC, '2', unsigned long)
#define WR_LM_FUN _IOWR(IOCTL_MAGIC, '3', unsigned long)

int main(void)
{
	// Startup
	int fd = open("/dev/lilium", O_RDWR);
	if (fd < 0)
	{
		printf("Cannot open device file /dev/lilium\n");
		return 1;
	}
	printf("Press any key for Ping...");
	getchar();

	// Ping
	unsigned long timeout = 3000;
	int result = 1337;
	struct lm_pkt_user ping_pkt = {
	    .opcode = LILIUM_PING_OPCODE,
	    .input = &timeout,
	    .output = &result,
	};
	int res = ioctl(fd, WR_LM_PING, &ping_pkt);
	if (res != 0)
	{
		printf("PING FAILURE: IOCTL failed, please check kernel log!\n");
		return 1;
	} else if (result != 0) {
		printf("PING FAILURE: Ping returns errno %i\n", result);
		return 1;
	} else {
		printf("PING SUCCESS: Ping returns %i\n", result);
	}

	printf("Press any key for v1...");
	getchar();

	// Call v1 prog and print result
	pid_t pid = 0;
	char prog_argv[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH] = { "", "USTH", "", "", ""};
	char prog_envp[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH] = { "", "", "", "", "" };
	struct lm_exec_data exec_data = {
		.sym = "prog",
		.ver = "v1",
		.argv = "",
		.envp = "",
	};
	memcpy(&(exec_data.argv[0]), prog_argv, sizeof(prog_argv));
	memcpy(&(exec_data.envp[0]), prog_envp, sizeof(prog_envp));
	struct lm_pkt_user exec_pkt = {
	    .opcode = LILIUM_EXEC_OPCODE,
	    .input = &exec_data,
	    .output = &pid,
	};
	res = ioctl(fd, WR_LM_EXEC, &exec_pkt);
	if (res != 0)
	{
		printf("EXEC_V1 FAILURE: IOCTL failed, please check kernel log!\n");
		return 1;
	} else if (pid <= 0) {
		printf("EXEC_V1 FAILURE: PID returns errno %i\n", pid);
		return 1;
	} else {
		printf("EXEC_V1 SUCCESS: PID returns %i\n", pid);
	}
	printf("Press any key for v2...");
	getchar();

	// Call v2 prog and print result
	char new_ver[] = "v2";
	memcpy(&(exec_data.ver), new_ver, sizeof(new_ver));
	res = ioctl(fd, WR_LM_EXEC, &exec_pkt);
	if (res != 0)
	{
		printf("EXEC_V2 FAILURE: IOCTL failed, please check kernel log!\n");
	} else if (pid <= 0) {
		printf("EXEC_V2 FAILURE: PID returns errno %i\n", pid);
	} else {
		printf("EXEC_V2 SUCCESS: PID returns %i\n", pid);
	}

	printf("Press any key for v1...");
	getchar();

	// Call v1 library and print result
	int fun_result;
	int val1 = 9;
	int val2 = 10;
	char fun_argv[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH] = { "", "", "", "", "" }; // bunch of NULL;
	memcpy(&(fun_argv[0]), &val1, sizeof(int));
	memcpy(&(fun_argv[1]), &val2, sizeof(int));

	struct lm_fun_data fun_data = {
		.ret_type = LILIUM_FUN_RET_INT,
		.input_size = 2,
		.sym = "libhelper",
		.ver = "v1",
		.name = "add",
		.argv = ""
	};
	memcpy(&(fun_data.argv[0]), fun_argv, sizeof(fun_argv));

	struct lm_ret fun_ret = {
		.val = ""
	};

	struct lm_pkt_user fun_pkt = {
		.opcode = LILIUM_FUN_OPCODE,
		.input = &fun_data,
		.output = &fun_ret,
	};

	res = ioctl(fd, WR_LM_FUN, &fun_pkt);
	int fun_ret_val = *(int *)(fun_ret.val);
	if (res != 0)
	{
		printf("FUN_V1 FAILURE: IOCTL failed, please check kernel log!\n");
		return 1;
	} else if (fun_ret_val == 0) {
		printf("FUN_V1 FAILURE: Function returns 0\n");
		return 1;
	} else {
		printf("FUN_V1 SUCCESS: Function returns %i\n", *((int *)fun_ret.val));
	}
	printf("Press any key for v2...");
	getchar();


	// Call v2 library and print result
	char another_ver[] = "v2";
	memcpy(&(fun_data.ver[0]), another_ver, sizeof(another_ver));
	res = ioctl(fd, WR_LM_FUN, &fun_pkt);
	fun_ret_val = *(int *)(fun_ret.val);
	if (res != 0)
	{
		printf("FUN_V2 FAILURE: IOCTL failed, please check kernel log!\n");
		return 1;
	} else if (fun_ret_val == 0) {
		printf("FUN_V2 FAILURE: Function returns 0\n");
		return 1;
	} else {
		printf("FUN_V2 SUCCESS: Function returns %i\n", fun_ret_val);
	}

	return 0;
}