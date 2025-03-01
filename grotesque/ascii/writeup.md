`scp -P2222 ascii@pwnable.kr:ascii .`
# Basic analysis
## hmmmm
```bash
silvermanium@silvermanium:~/Documents/pwnable/grotesque/ascii$ file ascii
ascii: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=5e22d460216b4409ecd523e0422e0eadd580b587, not stripped
```
## checksec
```bash
silvermanium@silvermanium:~/Documents/pwnable/grotesque/ascii$ checksec --file=ascii
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   2085) Symbols	  No	0		0		ascii
```
NX is enabled meaning shellcode on the stack cannot be executed. however i might be able to put shellcode on the heap.

# mmm
```bash
silvermanium@silvermanium:~/Documents/pwnable/grotesque/ascii$ python2 -c 'print "a" * 1000' | ./ascii
Input text : triggering bug...
Segmentation fault (core dumped)
```
# main
# Disassembled
```nasm
Dump of assembler code for function main:
   0x08048f0e <+0>:	push   %ebp
   0x08048f0f <+1>:	mov    %esp,%ebp
   0x08048f11 <+3>:	push   %ebx
   0x08048f12 <+4>:	and    $0xfffffff0,%esp
   0x08048f15 <+7>:	sub    $0x30,%esp
   0x08048f18 <+10>:	movl   $0x0,0x14(%esp)
   0x08048f20 <+18>:	movl   $0xffffffff,0x10(%esp)
   0x08048f28 <+26>:	movl   $0x32,0xc(%esp)
   0x08048f30 <+34>:	movl   $0x7,0x8(%esp)
   0x08048f38 <+42>:	movl   $0x1000,0x4(%esp)
   0x08048f40 <+50>:	movl   $0x80000000,(%esp)
   0x08048f47 <+57>:	call   0x805ac00 <mmap>
   0x08048f4c <+62>:	mov    %eax,0x28(%esp)
   0x08048f50 <+66>:	cmpl   $0x80000000,0x28(%esp)
   0x08048f58 <+74>:	je     0x8048f72 <main+100>
   0x08048f5a <+76>:	movl   $0x80c5608,(%esp)
   0x08048f61 <+83>:	call   0x8049a70 <puts>
   0x08048f66 <+88>:	movl   $0x1,(%esp)
   0x08048f6d <+95>:	call   0x8059f0c <_exit>
   0x08048f72 <+100>:	mov    $0x80c5620,%eax
   0x08048f77 <+105>:	mov    %eax,(%esp)
   0x08048f7a <+108>:	call   0x8049a40 <printf>
   0x08048f7f <+113>:	movl   $0x0,0x2c(%esp)
   0x08048f87 <+121>:	cmpl   $0x18f,0x2c(%esp)
   0x08048f8f <+129>:	ja     0x8048fba <main+172>
   0x08048f91 <+131>:	mov    0x2c(%esp),%eax
   0x08048f95 <+135>:	mov    0x28(%esp),%edx
   0x08048f99 <+139>:	lea    (%edx,%eax,1),%ebx
   0x08048f9c <+142>:	call   0x8049bf0 <getchar>
   0x08048fa1 <+147>:	mov    %al,(%ebx)
   0x08048fa3 <+149>:	movzbl (%ebx),%eax
   0x08048fa6 <+152>:	movsbl %al,%eax
   0x08048fa9 <+155>:	addl   $0x1,0x2c(%esp)
   0x08048fae <+160>:	mov    %eax,(%esp)
   0x08048fb1 <+163>:	call   0x8048ed0 <is_ascii>
   0x08048fb6 <+168>:	test   %eax,%eax
   0x08048fb8 <+170>:	jne    0x8048f87 <main+121>
   0x08048fba <+172>:	movl   $0x80c562e,(%esp)
   0x08048fc1 <+179>:	call   0x8049a70 <puts>
   0x08048fc6 <+184>:	call   0x8048eed <vuln>
   0x08048fcb <+189>:	mov    -0x4(%ebp),%ebx
   0x08048fce <+192>:	leave  
   0x08048fcf <+193>:	ret    

```
## Decompiled
```c
void main(void)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  uint uStack_14;
  
  iVar3 = mmap(0x80000000,0x1000,7,0x32,0xffffffff,0);
  if (iVar3 != -0x80000000) {
    puts(&UNK_080c5608);
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  printf(&UNK_080c5620);
  uStack_14 = 0;
  do {
    if (399 < uStack_14) break;
    pcVar1 = (char *)(uStack_14 + 0x80000000);
    cVar2 = getchar();
    *pcVar1 = cVar2;
    uStack_14 = uStack_14 + 1;
    iVar3 = is_ascii((int)*pcVar1);
  } while (iVar3 != 0);
  puts(&UNK_080c562e);
  vuln();
  return;
}
```
## Breakdown
`iVar3 = mmap(0x80000000,0x1000,7,0x32,0xffffffff,0);`
https://man7.org/linux/man-pages/man2/mmap.2.html
allocate 4096 bytes at 0x80000000 with read/write/exec permissions
```c
  do {
    if (399 < uStack_14) break;
    pcVar1 = (char *)(uStack_14 + 0x80000000);
    cVar2 = getchar();
    *pcVar1 = cVar2;
    uStack_14 = uStack_14 + 1;
    iVar3 = is_ascii((int)*pcVar1);
  } while (iVar3 != 0);
```
read 399 characters into 0x80000000
the function is_ascii allegedly checks whether each character is ascsii. might be critical
### 
# vuln
## decompiled
```c
void vuln(void)
{
  char local_ac [168];
  
  strcpy(local_ac,(char *)0x80000000);
  return;
}
```
# breakdown
Bofius Maximus
# O_o
