// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */

    char *path = get_word(dir);
    if (path == NULL) {
        fprintf(stderr, "cd: missing argument\n");
        return false;
    }

    if (chdir(path) != 0) {
        perror("cd");
        free(path);
        return false;
    }

    free(path);
    return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */

	/* TODO: If builtin command, execute the command. */

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	/* Sanity checks. */
    if (s == NULL || s->verb == NULL)
        return EXIT_FAILURE;

    /* Get the command name. */
    char *command = get_word(s->verb);
    if (command == NULL)
        return EXIT_FAILURE;

    /* If builtin command, execute the command. */
    if (strcmp(command, "cd") == 0) {
        int ret = shell_cd(s->params);
        free(command);
        return ret ? EXIT_SUCCESS : EXIT_FAILURE;
    } else if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
        free(command);
        return shell_exit();
    }

    /* If variable assignment, execute the assignment and return the exit status. */
    char *equal_sign = strchr(command, '=');
    if (equal_sign != NULL) {
        *equal_sign = '\0';
        char *value = equal_sign + 1;
        int ret = setenv(command, value, 1);
        free(command);
        return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* If external command: */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        free(command);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        /* Perform redirections in child */
        if (s->in != NULL) {
            char *in_file = get_word(s->in);
            int fd_in = open(in_file, O_RDONLY);
            if (fd_in < 0) {
                perror("open");
                exit(EXIT_FAILURE);
            }
            dup2(fd_in, STDIN_FILENO);
            close(fd_in);
            free(in_file);
        }

        // Handle output and error redirection
        if (s->out != NULL || s->err != NULL) {
            int fd;
            char *out_file = NULL;
            char *err_file = NULL;
            bool out_err_same = false;

            if (s->out != NULL) {
                out_file = get_word(s->out);
            }
            if (s->err != NULL) {
                err_file = get_word(s->err);
            }

            // Check if out and err redirect to the same file
            if (out_file != NULL && err_file != NULL && strcmp(out_file, err_file) == 0) {
                out_err_same = true;
            }

            if (out_err_same) {
                int flags = O_WRONLY | O_CREAT | ((s->io_flags & (IO_OUT_APPEND | IO_ERR_APPEND)) ? O_APPEND : O_TRUNC);
                fd = open(out_file, flags, 0644);
                if (fd < 0) {
                    perror("open");
                    exit(EXIT_FAILURE);
                }
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            } else {
                // Handle output redirection
                if (out_file != NULL) {
                    int flags = O_WRONLY | O_CREAT | ((s->io_flags & IO_OUT_APPEND) ? O_APPEND : O_TRUNC);
                    fd = open(out_file, flags, 0644);
                    if (fd < 0) {
                        perror("open");
                        exit(EXIT_FAILURE);
                    }
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }

                // Handle error redirection
                if (err_file != NULL) {
                    int flags = O_WRONLY | O_CREAT | ((s->io_flags & IO_ERR_APPEND) ? O_APPEND : O_TRUNC);
                    fd = open(err_file, flags, 0644);
                    if (fd < 0) {
                        perror("open");
                        exit(EXIT_FAILURE);
                    }
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                }
            }

            free(out_file);
            free(err_file);
        }

        /* Build argv */
        int argc;
        char **argv = get_argv(s, &argc);

        /* Load executable in child */
        execvp(argv[0], argv);
        perror("execvp");
        /* Free memory */
        for (int i = 0; i < argc; i++)
            free(argv[i]);
        free(argv);
        free(command);
        exit(EXIT_FAILURE);
    } else {
        /* Parent process */
        /* Wait for child */
        int status;
        waitpid(pid, &status, 0);
        free(command);
        /* Return exit status */
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        else
            return EXIT_FAILURE;
    }
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

	pid_t pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        return false;
    }

    if (pid1 == 0) {
        exit(parse_command(cmd1, level + 1, father));
    }

    pid_t pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        return false;
    }

    if (pid2 == 0) {
        exit(parse_command(cmd2, level + 1, father));
    }

    int status1, status2;
    waitpid(pid1, &status1, 0);
    waitpid(pid2, &status2, 0);

    return true;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */

	int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return false;
    }

    pid_t pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        return false;
    }

    if (pid1 == 0) {
        /* Child process for cmd1 */
        close(pipefd[READ]);
        dup2(pipefd[WRITE], STDOUT_FILENO);
        close(pipefd[WRITE]);
        exit(parse_command(cmd1, level + 1, father));
    }

    pid_t pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        return false;
    }

    if (pid2 == 0) {
        /* Child process for cmd2 */
        close(pipefd[WRITE]);
        dup2(pipefd[READ], STDIN_FILENO);
        close(pipefd[READ]);
        exit(parse_command(cmd2, level + 1, father));
    }

    close(pipefd[READ]);
    close(pipefd[WRITE]);
    int status1, status2;
    waitpid(pid1, &status1, 0);
    waitpid(pid2, &status2, 0);

    return true;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* Sanity checks */
    if (c == NULL)
        return EXIT_FAILURE;

    int ret1 = 0, ret2 = 0;

    if (c->op == OP_NONE) {
        /* Execute a simple command. */
        return parse_simple(c->scmd, level + 1, c);
    }

    switch (c->op) {
    case OP_SEQUENTIAL:
        /* Execute the commands one after the other. */
        ret1 = parse_command(c->cmd1, level + 1, c);
        ret2 = parse_command(c->cmd2, level + 1, c);
        return ret2;

    case OP_PARALLEL:
        /* Execute the commands simultaneously. */
        if (!run_in_parallel(c->cmd1, c->cmd2, level + 1, c))
            return EXIT_FAILURE;
        return EXIT_SUCCESS;

    case OP_CONDITIONAL_NZERO:
        /* Execute the second command only if the first one returns non-zero. */
        ret1 = parse_command(c->cmd1, level + 1, c);
        if (ret1 != 0)
            ret2 = parse_command(c->cmd2, level + 1, c);
        else
            ret2 = ret1;
        return ret2;

    case OP_CONDITIONAL_ZERO:
        /* Execute the second command only if the first one returns zero. */
        ret1 = parse_command(c->cmd1, level + 1, c);
        if (ret1 == 0)
            ret2 = parse_command(c->cmd2, level + 1, c);
        else
            ret2 = ret1;
        return ret2;

    case OP_PIPE:
        /* Redirect the output of the first command to the input of the second. */
        if (!run_on_pipe(c->cmd1, c->cmd2, level + 1, c))
            return EXIT_FAILURE;
        return EXIT_SUCCESS;

    default:
        return SHELL_EXIT;
    }

    return 0;
}
