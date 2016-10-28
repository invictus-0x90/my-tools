#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main()
{
	char str[] = "hello";
	write(0, str, strlen(str));
}
