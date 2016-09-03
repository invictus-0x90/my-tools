#include <dirent.h>
#include <stdio.h>
#include <signal.h>
#include <features.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sched.h>
#include <getopt.h>

#define SYSCALL_SEEN 0
#define CLONE_SEEN 2

/* function prologues */

/* Simple usage function */
void usage();


/* To find the pid of a shell process we open the proc directory
 * We then iterate through the folders in there, reading the status files
 * We want to look at the "Name: <binary>" field
 * This will tell us what program is associated with the pid
 * needle is the type process we want to attach to
 * not_pid is a pid we don't want to attach to, ie our current shell
*/
char* get_name_field(char *filename);


void trace_child(pid_t pid);


/* We need a linked list to hold the pid's of all programs to search for */
struct pid_struct
{
	pid_t pid;
	struct pid_struct *next;
}pid_struct;