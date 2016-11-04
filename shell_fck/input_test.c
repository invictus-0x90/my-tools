#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void *request_thread();

int main()
{
	pthread_t tid;
	pthread_create(&tid, NULL, &request_thread, NULL);

	while(1)
	{
		printf("Main\n");
		sleep(10);
	}
}


void *request_thread()
{
	char *in_buffer;
	unsigned int x;
	//memset(in_buffer, 0, sizeof(in_buffer));

	do
	{
		scanf("%s %d", in_buffer, &x);
		
		printf("buff = %s: %d\n", in_buffer, x);
		//free(in_buffer);
	}while(1);
}