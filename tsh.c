/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * This is a tiny shell that can support job control and do I/O redirection.
 * All builtin command are executed in the function builtin_cmd(), and
 * all the non-builtin command are executed by exceve() in eval().
 * There are three signal handlers that takes casre of SIGCHLD, SIGINT,
 * and SIGTSTP. The signals are blocked when necessary to ensure shell
 * performance.
 *
 * @author Zhichun Zhao <zhichun2@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
/**
 * @brief read through the command line and make further function calls
 *
 * The main funtion is the starting point of the function execution. It
 * initializes the job list, set up the signal handlers, and read the
 * command lines. It then calls functions like eval() to do job control.
 * The function returns 0 when it is successful.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != -1) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief handle background job control
 *
 * This function handles background job control, and supports I/O redirections.
 * All signals are blocked to ensure funtion performance. The return value is
 * true when the job is a builtin job and false otherwise.
 *
 */
void bg_cmd(const char *cmdline) {
    struct cmdline_tokens token;
    sigset_t prev, mask_all;
    sigfillset(&mask_all);
    parseline(cmdline, &token);
    sigprocmask(SIG_BLOCK, &mask_all, &prev);
    jid_t jid;
    pid_t pid;
    if (token.argc < 2) {
        printf("bg command requires PID or %%jobid argument\n");
        return;
    }
    // input is jid
    else if (sscanf(token.argv[1], "%%%d", &jid) == 1) {
        if (job_exists(jid)) {
            pid = job_get_pid(jid);
            const char *cmd = job_get_cmdline(jid);
            kill(-pid, SIGCONT);
            job_set_state(jid, BG);
            printf("[%d] (%d) %s\n", jid, pid, cmd);
        }
        // job does not exist
        else {
            printf("%%%d : No such job\n", jid);
        }
    }
    // input is pid
    else if (sscanf(token.argv[1], "%d", &pid) == 1) {
        kill(pid, SIGCONT);
        jid = job_from_pid(pid);
        if (jid != 0 && job_exists(jid)) {
            job_set_state(jid, BG);
            const char *cmd = job_get_cmdline(jid);
            printf("[%d] (%d) %s\n", jid, pid, cmd);
        } else {
            printf("(%d) : No such process\n", pid);
        }
    } else {
        printf("bg: argument must be a PID or %%jobid\n");
    }
    sigprocmask(SIG_BLOCK, &prev, NULL);
}

/**
 * @brief handle foreground job control
 *
 * This function handles foreground job control, and supports I/O redirections.
 * All signals are blocked to ensure funtion performance. The return value is
 * true when the job is a builtin job and false otherwise.
 *
 */
void fg_cmd(const char *cmdline) {
    struct cmdline_tokens token;
    sigset_t prev, mask_all;
    sigfillset(&mask_all);
    parseline(cmdline, &token);
    sigprocmask(SIG_BLOCK, &mask_all, &prev);
    jid_t jid;
    pid_t pid;
    // no jid/pid input
    if (token.argc < 2) {
        printf("fg command requires PID or %%jobid argument\n");
        return;
    }
    // input is jid
    else if (sscanf(token.argv[1], "%%%d", &jid) == 1) {
        if (job_exists(jid)) {
            pid = job_get_pid(jid);
            kill(-pid, SIGCONT);
            job_set_state(jid, FG);
            while (fg_job() != 0) {
                sigset_t mask_ict;
                sigfillset(&mask_ict);
                sigdelset(&mask_ict, SIGINT);
                sigdelset(&mask_ict, SIGTSTP);
                sigdelset(&mask_ict, SIGCHLD);
                sigsuspend(&mask_ict);
            }
        }
        // what to do when job doesn't exist
        else {
            printf("%%%d : No such job\n", jid);
        }
    }
    // input is pid
    else if (sscanf(token.argv[1], "%d", &pid) == 1) {
        kill(pid, SIGCONT);
        jid = job_from_pid(pid);
        if (jid != 0 && job_exists(jid)) {
            job_set_state(jid, FG);
            while (fg_job() != 0) {
                sigset_t mask_ict;
                sigfillset(&mask_ict);
                sigdelset(&mask_ict, SIGINT);
                sigdelset(&mask_ict, SIGTSTP);
                sigdelset(&mask_ict, SIGCHLD);
                sigsuspend(&mask_ict);
            }
        } else {
            printf("(%d) : No such process\n", pid);
        }
    } else {
        printf("fg: argument must be a PID or %%jobid\n");
    }
    sigprocmask(SIG_BLOCK, &prev, NULL);
}
/**
 * @brief handle all biltin commands
 *
 * This function handles all builtin commands, including quie, job, fg and bg
 * All signals are blocked to ensure funtion performance. The return value is
 * true when the job is a builtin job and false otherwise.
 *
 */
bool builtin_cmd(const char *cmdline) {
    struct cmdline_tokens token;
    sigset_t prev, mask_all;
    sigfillset(&mask_all);
    parseline(cmdline, &token);
    // quit the shell
    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
        return true;
    }
    if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask_all, &prev);
        int fd = STDOUT_FILENO;
        // output of job redirected
        if (token.outfile != NULL) {
            int retval;
            if ((fd = open(token.outfile, O_CREAT | O_TRUNC | O_WRONLY,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
                if (!access(token.outfile, R_OK | W_OK)) {
                    printf("%s: Permission denied\n", token.outfile);
                } else {
                    printf("%s: No such file or directory\n", token.outfile);
                }
                exit(0);
            }
            if (fd >= 0) {
                list_jobs(fd);
            } else if (fd < 0) {
                printf("%s: Permission denied\n", token.outfile);
            }
            if ((retval = close(fd)) < 0) {
                printf("%s: unable to close file or directory\n",
                       token.outfile);
                exit(1);
            }
        } else {
            list_jobs(STDOUT_FILENO);
        }

        sigprocmask(SIG_SETMASK, &prev, NULL);
        return true;
    }
    // background job
    if (token.builtin == BUILTIN_BG) {
        bg_cmd(cmdline);
        return true;
    }
    // foreground job
    if (token.builtin == BUILTIN_FG) {
        fg_cmd(cmdline);
        return true;
    }
    return false;
}
/**
 * @brief execute the job in commandline
 *
 * Eval function takes in command line, parse the input and store it in
 * a data structure called token. The command is executed according to
 * the input. When there is an error, there will be print messages.
 * It supports job control and I/O redirection. Signals are blocked
 * to ensure function performance.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    sigset_t mask, mask_all;
    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // execute builtin command
    builtin_cmd(cmdline);

    // non-builtin command
    if (token.builtin == BUILTIN_NONE) {
        sigfillset(&mask_all);
        sigprocmask(SIG_BLOCK, &mask_all, &mask);
        if ((pid = fork()) == 0) {
            // before execve, restore previous mask
            // unblock everything
            sigprocmask(SIG_UNBLOCK, &mask_all, NULL);
            // killing all children
            setpgid(0, 0);
            // input redirection
            if (token.infile != NULL) {
                int fd;
                int retval;
                if ((fd = open(token.infile, O_RDONLY)) < 0) {
                    if (!access(token.infile, R_OK)) {
                        printf("%s: Permission denied\n", token.infile);
                    } else {
                        printf("%s: No such file or directory\n", token.infile);
                    }
                    exit(0);
                }
                if (fd < 0) {
                    printf("%s: Permission denied\n", token.infile);
                    exit(0);
                }
                dup2(fd, STDIN_FILENO);
                if ((retval = close(fd)) < 0) {
                    printf("%s: unable to close file or directory\n",
                           token.infile);
                    exit(1);
                }
            }
            // output redirection
            if (token.outfile != NULL) {
                int fd;
                int retval;
                if ((fd = open(token.outfile, O_CREAT | O_TRUNC | O_WRONLY,
                               S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
                    if (!access(token.outfile, R_OK | W_OK)) {
                        printf("%s: Permission denied\n", token.outfile);
                    } else {
                        printf("%s: No such file or directory\n",
                               token.outfile);
                    }
                    exit(0);
                }
                if (fd < 0) {
                    printf("%s: Permission denied\n", token.outfile);
                    exit(0);
                }
                dup2(fd, STDOUT_FILENO);
                if ((retval = close(fd)) < 0) {
                    printf("%s: unable to close file or directory\n",
                           token.outfile);
                    exit(1);
                }
            }
            // actually doing the command
            if (execve(token.argv[0], token.argv, environ) < 0) {
                exit(0);
            }
        }
        // foreground jobs
        if (parse_result == PARSELINE_FG) {
            add_job(pid, FG, cmdline);
            while (fg_job() != 0) {
                sigset_t mask_ict;
                sigfillset(&mask_ict);
                sigdelset(&mask_ict, SIGINT);
                sigdelset(&mask_ict, SIGTSTP);
                sigdelset(&mask_ict, SIGCHLD);
                // wait for child to terminate
                sigsuspend(&mask_ict);
            }
            sigprocmask(SIG_SETMASK, &mask, NULL);
        } else {
            jid_t jid = add_job(pid, BG, cmdline);
            sigprocmask(SIG_SETMASK, &mask, NULL);
            printf("[%d] (%d) %s\n", jid, pid, cmdline);
        }
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief reape all child that has been terminated
 *
 * This function handle the children when they are terminated. It determines
 * how they stopped and react differently to different situations. Some
 * signals are blocked to ensure best performace. errors will be restored
 * at the end of the function.
 */
void sigchld_handler(int sig) {
    // reaping child
    int old_errno = errno;
    int status;
    pid_t pid;
    sigset_t mask, prev;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGINT);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        jid_t jid = job_from_pid(pid);
        // terminated normally
        if (WIFEXITED(status)) {
            delete_job(jid);
        }
        // TERMINATED BY SIGINT
        else if (WIFSIGNALED(status)) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            delete_job(jid);
        }
        // terminated by SIGTSTP
        else if (WIFSTOPPED(status)) {
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));
            if (jid != 0) {
                job_set_state(jid, ST);
            }
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
    errno = old_errno;
    return;
}

/**
 * @brief respond to SIGINT to terminate a process
 *
 * This function sends SIGINT to a process. Some signals are blocked to
 * ensure function performance. Errno is restored at the end of the function.
 */
void sigint_handler(int sig) {
    int old_errno = errno;
    sigset_t mask, prev;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        // send the SIGINT signal
        kill(-pid, SIGINT);
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = old_errno;
}

/**
 * @brief respond to SIGTSTP to stop a process
 *
 * This function sends SIGTSTP to a process. Some signals are blocked to
 * ensure function performance. Errno is restored at the end of the function.
 */
void sigtstp_handler(int sig) {
    int old_errno = errno;
    sigset_t mask, prev;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        // send the SIGTSTP signal
        kill(-pid, SIGTSTP);
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = old_errno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
