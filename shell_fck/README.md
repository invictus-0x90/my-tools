[!] To Do  
        - List all processes on the system and attach to a shell [done]  
        - Decide which process out of those to attach to [done]  
        - Add persistence such that the program is either tracing a child or scanning the process list waiting to attach [done]  
        - Add more functionality, ie injecting code into a running process, force the running of   arbitrary programs etc.  
        - Cleanup code and ensure it is secure    
	- Add error handling code such as if(ptrace(PTRACE_ATTACH....) != 0) {complain...}  


