# my tools 

[+] Shell_fck
	- This is a work in progress  
	- Currently this tool works by attaching to a given pid or will run /bin/sh itself  
	- It then messes with all output to the terminal by catching write syscalls  
	- More functionality to come with further development  
[!] To Do  
	- List all processes on the system and attach to a shell [done]  
	- Decide which process out of those to attach to  
	- Add persistence such that the program is either tracing a child or scanning the process list waiting to attach  
	- Add more functionality, ie injecting code into a running process, force the running of   arbitrary programs etc.
	- Cleanup code and ensure it is secure  
