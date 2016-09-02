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

#define SYSCALL_SEEN 0
#define CLONE_SEEN 2

void do_child(pid_t pid, char **argv)
{
	puts("[*] Setting up child [*]\n");

	/* Tell parent we are ready to be traced */
	ptrace(PTRACE_TRACEME, pid, 0,0);
	kill(getpid(), SIGSTOP);

	/* do execve and stuff */
	char *bin = "/bin/sh";
	execv(bin, argv);

}

void get_data(pid_t pid, unsigned long addr, struct user_regs_struct *regs)
{
	/* Allocate memory for storing data */
	char *val = malloc(4096);
	memset(val, 4096, 0);
	int index = 0;
	unsigned long tmp;

	/* allocate stuff for messing with the data */
	char str[] = "AAAAAAAA";
	long payload;

	while(index < 4096)
	{
		/* get the data at addr[index] */
		tmp = ptrace(PTRACE_PEEKDATA, pid, addr+index);

		/* store the data at that address in val */
		memcpy(val+index, &tmp, sizeof(long));

		if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
            		break;

		/* This is how we mess with the ouput */
		memcpy(&payload, str, 8);
		ptrace(PTRACE_POKEDATA, pid, regs->rsi+index, payload);

		index += sizeof(long);

	}
	printf("DATA FOUND:%s\n", val);
	free(val);

}

void do_fork(pid_t pid)
{
	int status = 0;
	struct user_regs_struct regs;

	/* Set options so that we can trace syscalls in this new child */
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	/* similar to syscall_seen */
	while(true)
	{
		/* Continue to next syscall and trap */
		ptrace(PTRACE_SYSCALL, pid, 0,0);

		waitpid(pid, &status, 0);

		/* If the child has stopped and it is a syscall */
		if(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
		{
			ptrace(PTRACE_GETREGS, pid, 0, &regs); //lets get the registers
			if(regs.orig_rax == 1) //sys_write
			{
				/* Here we can mess with the output */
				get_data(pid, regs.rsi, &regs);

				/* Continue to exit of child */
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
				waitpid(pid, &status, 0);
			}
		}
		/* Child exited */
       		if(WIFEXITED(status))
                {
                       printf("Child exiting...\n");
                       return;
                }

	}
}

bool new_child(int status)
{
	/* This is defined in the manpage for ptrace, we need to look for all events of a clone otherwise we may miss some */
	return (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) || (status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))  || (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8));
}

int syscall_seen(pid_t pid)
{
	int status = 0;
	/* Here we loop until we either see a syscall or a new child process is created */
	while(true)
	{
		/* Tell the child to continue until the next syscall */
		ptrace(PTRACE_SYSCALL, pid, 0,0);

		waitpid(pid, &status, 0); //wait for something to happen

		/* We want to see if the process has been trapped */
		if(WSTOPSIG(status) == SIGTRAP && WIFSTOPPED(status))
		{
			/* If the child has created a new child, we trace that until it exits.  defined in man(ptrace)*/
			if(new_child(status))
			{
				pid_t pid_child;
				/* Get the pid of the new child */
				ptrace(PTRACE_GETEVENTMSG, pid, 0, &pid_child);

				do_fork(pid_child); //do stuff on the grandchild
				return SYSCALL_SEEN; //return control to trace_child()
			}
		}
		if(WSTOPSIG(status) & 0x80 && WIFSTOPPED(status))
		{
			return SYSCALL_SEEN;
		}

		/* Child exited */
		if(WIFEXITED(status))
		{
			printf("Child exiting...\n");
			return 1;
		}
	}
}

void trace_child(pid_t pid)
{
	int status = 0, syscall, retval;
	struct user_regs_struct registers;

	/* These flags are needed to determine syscalls from systraps, and to trace clones */
	long flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

	waitpid(pid, &status, 0); //wait for sigstop
	ptrace(PTRACE_SETOPTIONS, pid, 0, flags); //set ptrace options, so we can get syscalls//	

	int flag;
	while(true)
	{
		/* Wait for the first sigtrap when a syscall is hit */
		if(syscall_seen(pid) != SYSCALL_SEEN) break;


		ptrace(PTRACE_GETREGS, pid, NULL, &registers);
		printf("[!] System(%d)\n", registers.orig_rax); //Need to map syscalls numbers to names

		/* If the sys_write is called from the child process, and not a grandchild */
		if(registers.orig_rax == 1)//1 = sys_write
		{
			/* We can mess with registers here */
			ptrace(PTRACE_GETREGS, pid, 0, &registers);
			/* get the data of a non-cloned write, ie pwd */
			get_data(pid, registers.rsi, &registers);
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);
			//At this point we could goto start_of_loop, only if we care about matching up syscalls and their returns
		}
		/* We can use the sys_stat call to find all programs run from cmdline */
		if(registers.orig_rax == 4) //stat
		{
			//printf("stat(%p, %p)\n", registers.rdi, registers.rsi);
			long tmp = ptrace(PTRACE_PEEKDATA, pid, registers.rdi);
			printf("stat(%s, 0x%p)\n", &tmp, registers.rsi);
		}
		/* We can find the pid of a grandchild from here [not really needed] */
		if(registers.orig_rax == 109) //sys_setpgid
		{
			printf("[!] Found pid of new process: %d\n", registers.rdi);
		}

		/* Here we grab the return value of the call */
		//if(syscall_seen(pid) != SYSCALL_SEEN) break;
		/* We can use the retval to match up calls -> returns */
		retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ORIG_RAX, NULL);
	}
}

int main(int argc, char **argv)
{
	pid_t pid;

	if(argc == 2)
	{
		pid = atoi(argv[1]);
		if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
		{
			printf("ATTACH_ERROR\n");
			exit(0);
		}
		trace_child(pid);
	}
	else
	{
		pid = fork();

		if(pid == 0)
		{
			do_child(pid, argv);
		}
		else
		{
			trace_child(pid);
		}
	}
}
