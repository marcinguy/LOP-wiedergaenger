#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int func()
{
  char *env[1] = {NULL};

  char *arguments[3]= { "/bin/sh",
                        "-i",
                        NULL
                      };
  execve("/bin/sh", arguments, env);
}


int main(int argc, char **argv)
{
  unsigned char *ptr;
  ptr = malloc(0x200000);


  unsigned long base = 0x7f2158;


  *(unsigned long long *)&ptr[base] = 0x00000000002b8+0x66;

  ptr[base + 0xa8] = 0xb8;

  ptr[base + 0x120] = 0xe3;


  return 0;
  //func();

}
