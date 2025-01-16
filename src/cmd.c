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

#define READ 0
#define WRITE 1

bool shell_cd(word_t *dir)
{
	// Get the path to the directory
	char *path = get_word(dir);

	if (!path) {
		perror("cd");
		return false;
	}

	// Change the directory
	if (chdir(path)) {
		perror("cd");
		free(path);
		return false;
	}
	free(path);
	return true;
}

int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */
	if (!s || !s->verb)
		return EXIT_FAILURE;

	/* Get the command name. */
	char *command = get_word(s->verb);

	if (!command)
		return EXIT_FAILURE;

	/* Save original file descriptors */
	int saved_stdin = dup(STDIN_FILENO);
	int saved_stdout = dup(STDOUT_FILENO);
	int saved_stderr = dup(STDERR_FILENO);

	// Handle input redirection
	if (s->in) {
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

	if (s->out || s->err) {
		// Handle output and error redirection
		int fd;
		char *out_file = NULL;
		char *err_file = NULL;
		bool out_err_same = false;

		if (s->out)
			out_file = get_word(s->out);

		if (s->err)
			err_file = get_word(s->err);

		// Check if out and err redirect to the same file
		if (out_file && err_file && !strcmp(out_file, err_file))
			out_err_same = true;

		if (out_err_same) {
			int flags = O_WRONLY | O_CREAT;

			if (s->io_flags & (IO_OUT_APPEND | IO_ERR_APPEND))
				// write at the end of the file
				flags |= O_APPEND;
			else
				// delete the content of the file before writing
				flags |= O_TRUNC;
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
			if (out_file) {
				int flags = O_WRONLY | O_CREAT;

				if (s->io_flags & IO_OUT_APPEND)
					// write at the end of the file
					flags |= O_APPEND;
				else
					// delete the content of the file before writing
					flags |= O_TRUNC;
				fd = open(out_file, flags, 0644);
				if (fd < 0) {
					perror("open");
					exit(EXIT_FAILURE);
				}
				dup2(fd, STDOUT_FILENO);
				close(fd);
			}

			// Handle error redirection
			if (err_file) {
				int flags = O_WRONLY | O_CREAT;

				if (s->io_flags & IO_ERR_APPEND)
					flags |= O_APPEND;
				else
					flags |= O_TRUNC;
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

	/* If builtin command, execute the command. */
	if (!strcmp(command, "cd")) {
		int ret = shell_cd(s->params);

		/* Restore original file descriptors */
		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stdin);
		close(saved_stdout);
		close(saved_stderr);
		free(command);

		if (ret)
			return EXIT_SUCCESS;
		else
			return EXIT_FAILURE;
	}

	if (!strcmp(command, "exit") || !strcmp(command, "quit")) {
		/* Restore original file descriptors */
		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stdin);
		close(saved_stdout);
		close(saved_stderr);
		free(command);
		return SHELL_EXIT;
	}

	/* If variable assignment, execute the assignment and return the exit status. */
	char *equal_sign = strchr(command, '=');

	if (equal_sign) {
		*equal_sign = '\0';
		char *value = equal_sign + 1;
		int ret = setenv(command, value, 1);

		/* Restore original file descriptors */
		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stdin);
		close(saved_stdout);
		close(saved_stderr);
		free(command);

		if (!ret)
			return EXIT_SUCCESS;
		else
			return EXIT_FAILURE;
	}

	/* If external command: */
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		free(command);
		return EXIT_FAILURE;
	}

    // child process is successful
	if (!pid) {
		/* Perform redirections in child */
		if (s->in) {
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
		if (s->out || s->err) {
			int fd;
			char *out_file = NULL;
			char *err_file = NULL;
			bool out_err_same = false;

			if (s->out)
				out_file = get_word(s->out);

			if (s->err)
				err_file = get_word(s->err);

			// Check if out and err redirect to the same file
			if (out_file && err_file && !strcmp(out_file, err_file))
				out_err_same = true;

			if (out_err_same) {
				int flags = O_WRONLY | O_CREAT;

				if (s->io_flags & (IO_OUT_APPEND | IO_ERR_APPEND))
					flags |= O_APPEND;
				else
					flags |= O_TRUNC;
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
				if (out_file) {
					int flags = O_WRONLY | O_CREAT;

					if (s->io_flags & IO_OUT_APPEND)
						flags |= O_APPEND;
					else
						flags |= O_TRUNC;
					fd = open(out_file, flags, 0644);
					if (fd < 0) {
						perror("open");
						exit(EXIT_FAILURE);
					}
					dup2(fd, STDOUT_FILENO);
					close(fd);
				}

				// Handle error redirection
				if (err_file) {
					int flags = O_WRONLY | O_CREAT;

					if (s->io_flags & IO_ERR_APPEND)
						flags |= O_APPEND;
					else
						flags |= O_TRUNC;
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

		// If execvp returns, an error occurred
		fprintf(stderr, "Execution failed for '%s'\n", argv[0]);

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

		/* Restore original file descriptors */
		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stdin);
		close(saved_stdout);
		close(saved_stderr);
		free(command);

		/* Return exit status */
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		else
			return EXIT_FAILURE;
	}
}

bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
    // create process 1
	pid_t pid1 = fork();

	if (pid1 < 0) {
		perror("fork");
		return false;
	}

	if (!pid1)
		exit(parse_command(cmd1, level + 1, father));

    // create process 2
	pid_t pid2 = fork();

	if (pid2 < 0) {
		perror("fork");
		return false;
	}

	if (!pid2)
		exit(parse_command(cmd2, level + 1, father));

	int status1, status2;

    // wait for both processes to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return true;
}

int run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
					   command_t *father)
{
	int pipefd[2];
	pid_t pid1, pid2;
	int status1 = 0, status2 = 0;

	if (pipe(pipefd) == -1) {
		perror("pipe");
		return EXIT_FAILURE;
	}

    // create process 1
	pid1 = fork();
	if (pid1 < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}

	if (!pid1) {
		close(pipefd[READ]);
		// output of cmd1 is redirected to the write end of the pipe
		dup2(pipefd[WRITE], STDOUT_FILENO);
		close(pipefd[WRITE]);
		exit(parse_command(cmd1, level + 1, father));
	}

    // create process 2
	pid2 = fork();
	if (pid2 < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}

	if (!pid2) {
		close(pipefd[WRITE]);
		// input of cmd2 is redirected to the read end of the pipe
		dup2(pipefd[READ], STDIN_FILENO);
		close(pipefd[READ]);
		exit(parse_command(cmd2, level + 1, father));
	}

	close(pipefd[READ]);
	close(pipefd[WRITE]);

    // wait for both processes to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// if cmd1 or cmd2 did not terminate normally, return EXIT_FAILURE
	if (!WIFEXITED(status1) || !WIFEXITED(status2))
		return EXIT_FAILURE;

	if (WIFEXITED(status1) && WIFEXITED(status2))
		return WEXITSTATUS(status2);

    // If only cmd1 finished normally, we return status1
	if (WIFEXITED(status1))
		return WEXITSTATUS(status1);

    // If only cmd2 finished normally, we return status2
	if (WIFEXITED(status2))
		return WEXITSTATUS(status2);

    // should not be reached here normally
	return EXIT_FAILURE;
}

int parse_command(command_t *c, int level, command_t *father)
{
	/* Sanity checks */
	if (!c)
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
		if (ret1)
			ret2 = parse_command(c->cmd2, level + 1, c);
		else
			ret2 = ret1;
		return ret2;

	case OP_CONDITIONAL_ZERO:

		/* Execute the second command only if the first one returns zero. */
		ret1 = parse_command(c->cmd1, level + 1, c);
		if (!ret1)
			ret2 = parse_command(c->cmd2, level + 1, c);
		else
			ret2 = ret1;
		return ret2;

	case OP_PIPE:

		/* Redirect the output of the first command to the input of the second. */
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

	default:
		return SHELL_EXIT;
	}

	return 0;
}
