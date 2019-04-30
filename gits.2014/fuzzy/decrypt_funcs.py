#!/usr/bin/python

from binaryninja import *

MY_SENDALL          = 0x602160
MY_READALL          = 0x602620
MY_READUNTIL        = 0x602a60
INTRO               = 0x602e20
CHARHISTOGRAM       = 0x603160
ISSORTED            = 0x6034e0
ISSORTEDREVERSE     = 0x603740
ISSORTEDINTS        = 0x6039a0
ISSORTEDINTSREVERSE = 0x603ca0
FINDNUMBERS         = 0x603fa0

funcs = [
    MY_SENDALL,
    MY_READALL,
    MY_READUNTIL,
    INTRO,
    CHARHISTOGRAM,
    ISSORTED,
    ISSORTEDREVERSE,
    ISSORTEDINTS,
    ISSORTEDINTSREVERSE,
    FINDNUMBERS
]

bv = BinaryViewType['ELF'].open('./fuzzy')
br = BinaryReader(bv)
bw = BinaryWriter(bv)

for func in funcs:
    nops = False
    br.seek(func)
    bw.seek(func)
    while True:
        bw.write8(~br.read8())
        if (br.offset - func) > 6:
            br.seek_relative(-6)
            if br.read(6) == '\x90' * 6:
                nops = True
        if nops == True:
            br.seek_relative(-1)
            if br.read(1) == '\xc3':
                bv.create_user_function(func)
                break

bv.create_database('./fuzzy.bndb')
