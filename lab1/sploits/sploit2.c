#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	/*

	INFO FROM GDB:

		% info frame
			Arglist at 0x2021fee0, args: argc=1, argv=0x7fffffffdf98
 			Locals at 0x2021fee0, Previous frame's sp is 0x2021fef0
 			Saved registers:
  			rbp at 0x2021fee0, rip at 0x2021fee8

  		% p &buf
  			0x2021fda0
	*/

	args[0] = TARGET;
	args[1] = "hi there";
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
