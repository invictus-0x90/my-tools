#include "shell_fck.h"

/* To find the pid of a shell process we open the proc directory
 * We then iterate through the folders in there, reading the status files
 * We want to look at the "Name: <binary>" field
 * This will tell us what program is associated with the pid
 * needle is the type process we want to attach to
 * not_pid is a pid we don't want to attach to, ie our current shell
*/
struct pid_struct* find_process(char *needle, pid_t not_pid)
{
	char filename[256]; //buffer for filename

	/* Bit of linked list setup */
	struct pid_struct *root = (struct pid_struct *) malloc(sizeof(pid_struct));
	struct pid_struct *p = root;

	struct dirent *p_dirent;
	DIR *dir;

	memset(filename, 0, sizeof(filename));

	if((dir = opendir("/proc/")) == NULL)
	{
		printf("[!] Could not open directory [!]\n");
		return NULL;
	}

	/* iterate past the first few entries of the process directory */
	while((p_dirent = readdir(dir)) != NULL)
	{
		if(strcmp(p_dirent->d_name, "1") == 0) //we want to find the first process
			break;
	}

	/* read the status files of the processes until we get a shell process */
	while((p_dirent = readdir(dir)) != NULL)
	{
		/* set the filename up ready to open the status file */
		strcpy(filename, "/proc/");
		strcat(filename, p_dirent->d_name);
		strcat(filename, "/status");

		char *program = get_name_field(filename);
	
		/* DEBUG */
		//printf("%s: %s\n", filename, program);

		if(strncmp(program, needle, sizeof(needle)) == 0)
		{
			printf("[+] Found %s process pid: %s [+]\n", needle, p_dirent->d_name);
			
			/*add that pid to the pid_struct, typical linked list */
			p->pid = atoi(p_dirent->d_name);
			p->next = (struct pid_struct *) malloc(sizeof(pid_struct));
			p = p->next;
		}
		
		memset(filename, 0, sizeof(filename)); //reset filename
	}
	closedir(dir);

	p = root;
	return p;
	/*DEBUG */
	p = root;
	while(p->next != NULL)
	{
		printf("%d\n", p->pid);
		p = p->next;
	}
	
}

/* We want to get the name associated with the pid */
char* get_name_field(char *filename)
{
	FILE *fp;
	char buff[50];

	memset(buff, 0, sizeof(buff));
	char *b = buff;

	if((fp = fopen(filename, "r")) == NULL)
	{
		return NULL;
	}

	fseek(fp, 6, SEEK_CUR); //seek past the "Name:\t" field

	fgets(buff, 40, fp); //grab the name, 40 bytes is more than enough
	fclose(fp);

	int i = 0;
	while(buff[++i] != '\n'); //handle the trailing new line

	buff[i] = '\00';
	
	return b;

}

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
	char str[] = "trololol";
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
	//printf("DATA FOUND:%s\n", val);
	free(val);

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
				printf("[!] Process is spawning a new child. pid: %d\n", pid_child);
				
				trace_child(pid_child);
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
		//printf("[!] System(%d)\n", registers.orig_rax); //Need to map syscalls numbers to names

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
			//printf("stat(%s, 0x%p)\n", &tmp, registers.rsi);
		}
		/* We can find the pid of a grandchild from here [not really needed] */
		if(registers.orig_rax == 109) //sys_setpgid
		{
			//printf("[!] Found pid of new process: %d\n", registers.rdi);
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
	char *process_name;
	
	/* use for friendly options parsing */	
	struct option long_options[] = 
	{
		{"pid", required_argument, 0, 'p'},
		{"process_name", required_argument, 0, 'n'},
		{"help", no_argument, 0, 'h'}
	};

	/* if user didn't give args, we just run the shell ourselves */
	if(argc == 1)
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
	/* Otherwise, parse the users options and go from there */
	else
	{
		int option;
		int long_index = 0;
		char *value;
		while((option = getopt_long(argc, argv, "p:n:h", long_options, &long_index)) != -1)
		{
			switch(option)
			{
				case 'p':
					pid = atoi(optarg);
					printf("[+] Attempting to attach to pid: %d [+]\n", pid);

					if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
					{
						printf("[!] ATTACH_ERROR [!]\n");
						exit(0);
					}

					trace_child(pid);

					break;
				case 'n':
					process_name = optarg;
					struct pid_struct *current_pids = find_process(process_name, 0);
					break;
				case 'h':
					usage();
					break;
			}
		}
	}

}

/* usage function */
void usage()
{
	printf("Example Uses\n[1] ./shell_fck -p <pid_to_attach>\n[2] ./shell_fck -n <name_of_process> (ie sh, zsh, bash...)\n");
}