#!/usr/bin/env python3
import os
import re
import subprocess
import sys

TARGET_DIR = os.path.dirname(os.path.abspath(__file__))
IMG_PATH = os.path.join(TARGET_DIR, "teller_ws.img")
EXPECTED_FLAG = "FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}"

DEBUGFS = "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"
if not os.path.exists(DEBUGFS):
    DEBUGFS = "debugfs"

def solve_with_debugfs():
    print("[*] Method 1: Checking deleted inodes with debugfs...")
    try:
        res = subprocess.run(
            [DEBUGFS, "-R", "lsdel", IMG_PATH],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("--- debugfs lsdel output ---")
        print(res.stdout)
        
        # Parse deleted inode numbers from lsdel output
        inodes = re.findall(r'^\s*(\d+)\s+', res.stdout, re.MULTILINE)
        print(f"[+] Found deleted inodes: {inodes}")
        
        for ino in inodes:
            dump_res = subprocess.run(
                [DEBUGFS, "-R", f"dump <{ino}> /dev/stdout", IMG_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            content = dump_res.stdout.decode('utf-8', errors='ignore')
            if "FLAG{" in content:
                print(f"[+] Flag recovered from inode <{ino}>!")
                return content
    except Exception as e:
        print(f"[-] debugfs method error: {e}")
    return None

def solve_with_carving():
    print("[*] Method 2: Raw data block carving / string scan...")
    with open(IMG_PATH, "rb") as f:
        data = f.read()
    
    match = re.search(r"FLAG\{[^}]+\}", data.decode('latin-1'))
    if match:
        flag = match.group(0)
        print(f"[+] Flag carved from disk image: {flag}")
        return flag
    return None

def main():
    if not os.path.exists(IMG_PATH):
        print(f"[-] Image file not found at {IMG_PATH}. Run build.py first.")
        sys.exit(1)
        
    recovered_flag = None
    
    # Try debugfs recovery
    debugfs_res = solve_with_debugfs()
    if debugfs_res:
        flag_match = re.search(r"FLAG\{[^}]+\}", debugfs_res)
        if flag_match:
            recovered_flag = flag_match.group(0)

    # Fallback / verification via carving
    if not recovered_flag:
        recovered_flag = solve_with_carving()
        
    print("\n==========================================")
    if recovered_flag == EXPECTED_FLAG:
        print(f"SUCCESS: Flag correctly recovered: {recovered_flag}")
        sys.exit(0)
    else:
        print(f"FAILED: Expected {EXPECTED_FLAG}, got {recovered_flag}")
        sys.exit(1)

if __name__ == "__main__":
    main()
