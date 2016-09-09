

struct pid_struct *create_pid_struct(pid_t pid, char *buff, bool is_child, struct pid_struct *n);

/* We need a linked list to hold the pid's of all programs to search for */
struct pid_struct
{
	pid_t pid; //store the pid
	bool is_child; //used to determine if this proc is a child of another proc
	char proc_name[50]; //store the program associated with the pid
	struct pid_struct *next; //pointer to next pid
}pid_struct;

/* Simple hash table to store pid_structs */
struct pid_hash_table
{
	struct pid_struct table[500];
	int size;
}pid_hash_table;

struct pid_struct *create_pid_struct(pid_t pid, char *buff, bool is_child, struct pid_struct *n)
{
	struct pid_struct *new_pid = (struct pid_struct *)malloc(sizeof(pid_struct));

	new_pid->pid = pid;
	new_pid->is_child = is_child;
	new_pid->next = n;
	strcpy(new_pid->proc_name, buff);

	return new_pid;
}

