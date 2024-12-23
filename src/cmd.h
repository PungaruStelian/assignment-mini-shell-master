/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _CMD_H
#define _CMD_H

#include "../util/parser/parser.h"

#define SHELL_EXIT -100

/**
 * Parse and execute a command.
 */
int parse_command(command_t *cmd, int level, command_t *father);

/**
 * Internal change-directory command.
 */
bool shell_cd(word_t *dir);

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
int parse_simple(simple_command_t *s, int level, command_t *father);

/**
 * Process two commands in parallel, by creating two children.
 */
bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father);

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
int run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father);

#endif /* _CMD_H */
