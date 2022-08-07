from pwn import *
import exploit_helper

# Binary filename
exe = "/bin/netcat"
server_ip = "104.248.173.13"
server_port = "30633"

# Specify GDB script here (breakpoints etc.)
gdb_script = '''
piebase
'''.format(**locals())

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = exploit_helper.start(exe=exe, gdb_script=gdb_script, argv=[server_ip, server_port])

io.readuntil(b"/ $ ")

io.interactive()

