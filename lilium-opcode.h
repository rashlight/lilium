/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _LINUX_LILIUM_OPCODE_H
#define _LINUX_LILIUM_OPCODE_H

#define LILIUM_RECEIVE_OPCODE 0 	/* Received payload from plugin */
#define LILIUM_PING_OPCODE 1 		/* Check plugin exists */
#define LILIUM_REGISTER_OPCODE 2 	/* Register plugin */
#define LILIUM_UNREGISTER_OPCODE 3 	/* Unregister plugin */
#define LILIUM_EXEC_OPCODE 4 		/* Execute process */
#define LILIUM_FUN_OPCODE 5 		/* Execute function in library */

#endif