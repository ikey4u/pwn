```
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

这道题的意思是说, 输入 20 个字符, 然后把存储这 20 个字符的内存转换成 int 型指针,
程序是 32 bits 的, 由于每个 int 占 4 字节, 因此一共会得到 5 个整数, 如果这 5 个整数累加得到
的值为 0x21DD09EC, 那么校验通过.

刚开始用了 1 * 4 + 0x21dd09e8 = 0x21DD09EC 来得到五个数:

```
➜  pwnable.kr printf '\x1\x0\x0\x0\x0\x1\x0\x0\x0\x0\x1\x0\x0\x0\x0\x1\x0\x0\x0\x0\xe8\x9\xdd\x21' | hexdump
0000000 01 00 00 00 00 01 00 00 00 00 01 00 00 00 00 01
0000010 00 00 00 00 e8 09 dd 21
0000018
```

但是这犯了一个低级错误, 就是 NULL 字符, 在 strlen 这里就过不去了, 因此我就把所有 `\x0` 都
转换为 `\x1` 变成了 0x01010101 * 4 + 0x1dd905e8 = 0x21DD09EC, 于是成功通过

```
col@ubuntu:~$ ./col `printf '\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xe8\x05\xd9\x1d'`
daddy! I just managed to create a hash collision :)
```
