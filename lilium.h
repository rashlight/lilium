// SPDX-License-Identifier: GPL-2.0

/*
 * lilium - a project to unify programs and libraries (header file).
 * Copyright (c) 2024 An Van Quoc <andtf2002@gmail.com>
 */

#include <linux/types.h>
#include "lilium-opcode.h"

#ifndef _LINUX_LILIUM_H
#define _LINUX_LILIUM_H

#define LILIUM_SYMBOL_LENGTH 128 /* Usable size is 127 due to string terminated with NULL */
#define LILIUM_MAX_ARGS 5 /* One for symbol path, 4 for custom */
#define LILIUM_MAX_SIZE LILIUM_SYMBOL_LENGTH * 13 // 12 + 1 for NULL padding

#define LILIUM_FUN_RET_VOID 0 /* Function returning nothing */
#define LILIUM_FUN_RET_INT 1 /* Function returning integer */
#define LILIUM_FUN_RET_CHARPTR 2 /* Function returning char pointer */

/*
 * The ioctl data type for Lilium
 * Use for module to client and client to module communication.
 * The userspace must allocate memory for one input and one output exactly as the function definition.
 * When calling ioctl, note that any pointers will NOT be usable, use an array and copy data instead.
 * If input and/or output is not needed, set it to NULL.
 */
struct lm_pkt_user {
	int opcode; // Operation code
	void *input; // Pointer to input
	void *output; // Pointer to output
};

/*
 * The input data type for Lilium
 * Use for kernel to plugin communication.
 */
struct lm_pkt_module {
	int opcode; // Operation code
	char data[LILIUM_MAX_SIZE]; // Data as charater stream
};

/*
 * The variable return data type for Lilium
 */
struct lm_ret {
	char val[LILIUM_MAX_SIZE];
};

/*
 * The input data type for Lilium
 * Use for plugin to module communication.
 */
struct lm_pkt_plugin {
	int opcode; // Operation code
	char data[LILIUM_MAX_SIZE]; // Data as charater stream
};

/*
 * Data for lm_exec
 */
struct lm_exec_data {
	char sym[LILIUM_SYMBOL_LENGTH]; // symbol name (program or library)
	char ver[LILIUM_SYMBOL_LENGTH]; // version string
	char argv[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH]; // argument values
	char envp[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH]; // environment variables
};

/*
 * Data for lm_fun
 */
struct lm_fun_data {
	unsigned int ret_type;
	unsigned int input_size;
	char sym[LILIUM_SYMBOL_LENGTH]; // symbol name (program or library)
	char ver[LILIUM_SYMBOL_LENGTH]; // version string
	char name[LILIUM_SYMBOL_LENGTH]; // function name
	char argv[LILIUM_MAX_ARGS][LILIUM_SYMBOL_LENGTH]; // argument values
};

/*
 * Check if the module can contact with the plugin.
 * Return 0 on success, errno if not connected or failed.
 */
int lm_ping(unsigned int);

/*
 * Register the process to handle plugin connection.
 * This operation can only be done by the superuser.
 * Return 0 on success, errno if failed.
 */
int lm_register(void);

/*
 * Unregister the process handle plugin connection.
 * This operation can only be done by the superuser.
 * Return 0 on success, errno if failed.
 */
int lm_unregister(void);

/*
 * Execute a program with the specified symbol (program name), version and arguments.
 * Returns the pid if successfully executed, errno if failed.
 * Note that this does not mean that a process returns success, it just mean the process has ran.
 */
pid_t lm_exec(struct lm_exec_data data);

/*
 * Execute a function with the specified symbol (library), name and arguments.
 * Returns the payload if successful, NULL if failed.
 */
struct lm_ret lm_fun(struct lm_fun_data data);

#endif