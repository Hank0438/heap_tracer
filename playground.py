from pwn import *

r = process("./playground.c")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")


def malloc(num):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(": ")
    r.sendline(str(num))

def fill_chunk(num):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(": ")
    r.sendline(str(num))

def free(num):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(": ")
    r.sendline(str(num))

def uaf(num):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(": ")
    r.sendline(str(num))

def overflow(num, overflow_num):
    r.recvuntil(">")
    r.sendline("5")
    r.recvuntil(": ")
    r.sendline(str(num))

def fake_free():
    r.recvuntil(">")
    r.sendline("6")
    r.recvuntil(": ")
    r.sendline(str(num))

malloc(0)
r.interactive()