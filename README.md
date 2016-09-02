# my tools 

[+] Shell_fck
	- This is a work in progress
	- Currently this tool works by attaching to a given pid or will run /bin/sh itself
	- It then messes with all output to the terminal by catching write syscalls
[!] To Do
	- List all processes on the system and attach to a shell
	- Reattach if the process is killed
	- Add more functionality, ie injecting code into a running process, force the running of arbitrary programs etc.