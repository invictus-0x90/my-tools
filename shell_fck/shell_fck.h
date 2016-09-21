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
#include <pthread.h>
#include "pid_utils.h"

#define SYSCALL_SEEN 0
#define CLONE_SEEN 2


/* function prologues */

/* Simple usage function */
void usage();




void update_hash_table(struct pid_struct *current_pids, struct pid_hash_table *current_table);

bool in_table(pid_t pid, struct pid_hash_table *table)
{
	struct pid_struct *tmp = table->table[pid%500];
	if(tmp == NULL)
		return false;

	while(tmp->next != NULL)
	{
		if(tmp->pid == pid)
			return true;

		tmp = tmp->next;
	}
	return false;
}

void remove_from_table(struct pid_struct *pid_delete, struct pid_struct *root)
{
	struct pid_struct *p = root;
	struct pid_struct *prev;
	while(p != NULL)
	{
		/* Look for the pid to delete */
		if(p->next == NULL)
		{
			if(pid_delete != NULL) //paranoid
				free(pid_delete);
			return;
		}
		else if(compare_pids(p->next, pid_delete))
		{
			p->next = pid_delete->next;
			if(pid_delete != NULL) //paranoid
				free(pid_delete);
			return;
		}
		p = p->next;
	}
}

void clear_table(struct pid_hash_table *table)
{
	bool inc_tmp = true;

	for(int i = 0; i < table->size; i++)
	{
		struct pid_struct *tmp = table->table[i];
		struct pid_struct *p = tmp;

		if(tmp != NULL && tmp->next == NULL) //only process in bucket
		{
			if(!tmp->being_traced) //we dont want to free traced processes
			{
				free(tmp);
				table->table[i] = NULL;
			}
		}
		else
		{
			while(tmp != NULL) //iterate over list
			{
				if(!tmp->being_traced) //end of list
				{
					if(tmp->next == NULL)
					{
						if(tmp == table->table[i])
						{
							free(tmp);
							table->table[i] = NULL;
							break;
						}
						else
						{
							free(tmp);
							p->next = NULL;
							break;
						}
					}
					else //if tmp->next is not null
					{
						if(tmp == table->table[i]) //if tmp is the first proc in the bucket and tmp->next isnt null
						{
							p = tmp->next;
							free(tmp);
							table->table[i] = p;
							tmp = p;
							inc_tmp = false;
						}
						else
						{
							p->next = tmp->next;
							free(tmp);
							tmp = p;
							inc_tmp = true;
						}
					}
				}
				if(inc_tmp)
				{
					p = tmp;
					tmp = tmp->next;
				}
				else
				{
					p = tmp;
					inc_tmp = true;
				}

			}
				
		}
	}
	
}

/* To find the pid of a shell process we open the proc directory
 * We then iterate through the folders in there, reading the status files
 * We want to look at the "Name: <binary>" field
 * This will tell us what program is associated with the pid
 * needle is the type process we want to attach to
 * not_pid is a pid we don't want to attach to, ie our current shell
*/
bool get_name_field(char *filename, char *buff);







void *init_thread(void *args);








struct pid_struct* find_process(char *needle, struct pid_hash_table *current_table);







void do_child(pid_t pid, char **argv);






void get_data(pid_t pid, unsigned long addr, struct user_regs_struct *regs);






bool new_child(int status);



int syscall_seen(struct pid_struct *proc);





void trace_child(struct pid_struct *proc);

/* This is an init function used for pthread_create
 * Using this function means we don't have to mess with trace_child
 * The process has to be attached here otherwise the thread has no access to it.
*/
void *init_thread(void *args);




int main(int argc, char **argv);

