import argparse
import multiprocessing
import subprocess

import itertools

parser = argparse.ArgumentParser(prog="bruteforce",
                                 description="Hash brute forcer for HTB Kernel Adventures Pt 1.")
parser.add_argument("hash", type=int)
args = parser.parse_args()

CHARACTERS = "abcdefghijklmnopqrstuvwxyz"


def generate_password(length):
    res = itertools.permutations(CHARACTERS, length)
    for g in res:
        yield "".join(g)


def check_hash(password):
    current_hash = subprocess.run(f"cmake-build-debug/hash {password}",
                                  shell=True)

    if current_hash == args.hash:
        print(f"DISCOVERED VALID PASSWORD: {password}")
        return password

    return None


with multiprocessing.Pool(6) as p:
    for current_length in range(5, 9):
        print(f"Working on length: {current_length}")
        results = p.imap_unordered(check_hash, generate_password(current_length))

        for result in results:
            if result is not None:
                print(f"DISCOVERED VALID PASSWORD: {result}")
                p.close()
                exit(1)
            del result
