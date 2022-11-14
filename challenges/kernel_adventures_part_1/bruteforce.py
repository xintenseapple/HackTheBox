import argparse
import multiprocessing
import subprocess

import itertools

parser = argparse.ArgumentParser(prog="bruteforce",
                                 description="Hash brute forcer for HTB Kernel Adventures Pt 1.")
parser.add_argument("hash", type=int)
args = parser.parse_args()

CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


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


with multiprocessing.Pool(8) as p:
    for current_length in range(4, 12):
        print(f"Working on length: {current_length}")
        results = p.map(check_hash, generate_password(current_length))

        filter(lambda v: v is not None, results)

        print(f"Results: {', '.join(results)}")
