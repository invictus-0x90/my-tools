# my tools 

[+] Shell_fck
	- This was a project I did to understand using ptrace.
	- It works by iterating over all the process in /proc, putting them in a hash table, and then attaching to any
	that are of interest. Basically it at the moment it attaches to every bash shell process on the system.
	- It then messes with any output as show in the gif below. It will also attach to any new processes that spawn whilst
	it is running.
	- Has to be run as root to attach to any user's process.
	- Its a pretty simple PoC, in reality, you could catch any syscall you want and inject your own code into the process.

![alt tag](https://raw.githubusercontent.com/invictus-0x90/my-tools/master/example.gif)
