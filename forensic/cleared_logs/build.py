#!/usr/bin/env python3
import os
import subprocess
import sys

TARGET_DIR = os.path.dirname(os.path.abspath(__file__))
IMG_PATH = os.path.join(TARGET_DIR, "teller_ws.img")
IMG_SIZE_MB = 300

# Locate binaries
MKE2FS = "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs"
DEBUGFS = "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"

if not os.path.exists(MKE2FS):
    MKE2FS = "mke2fs"
if not os.path.exists(DEBUGFS):
    DEBUGFS = "debugfs"

def create_image():
    print(f"[+] Creating empty {IMG_SIZE_MB}MB disk image at {IMG_PATH}...")
    with open(IMG_PATH, "wb") as f:
        f.truncate(IMG_SIZE_MB * 1024 * 1024)

    print("[+] Formatting image with ext4 (TELLER_WS)...")
    cmd_mkfs = [
        MKE2FS,
        "-t", "ext4",
        "-F",
        "-L", "TELLER_WS",
        "-b", "4096",
        IMG_PATH
    ]
    res = subprocess.run(cmd_mkfs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"[-] mke2fs failed: {res.stderr}")
        sys.exit(1)

    print("[+] Populating ext4 filesystem structure via debugfs...")
    
    # Write temp files to inject into image
    temp_dir = os.path.join(TARGET_DIR, "_tmp_files")
    os.makedirs(temp_dir, exist_ok=True)
    
    bash_history_path = os.path.join(temp_dir, ".bash_history")
    daily_report_path = os.path.join(temp_dir, "daily_report.txt")
    adjust_script_path = os.path.join(temp_dir, "adjust_balances.sh")
    targets_path = os.path.join(temp_dir, "targets.txt")
    
    with open(bash_history_path, "w") as f:
        f.write("ls -la\ncat daily_report.txt\n./post_adjustment --help\nrm adjust_balances.sh targets.txt\nhistory -c\n")
        
    with open(daily_report_path, "w") as f:
        f.write("TELLER DAILY REPORT - BRANCH #402\nDate: 2026-08-05\nStatus: All registers balanced at 17:00.\nNo anomalies reported during shift.\n")
        
    with open(adjust_script_path, "w") as f:
        f.write("#!/bin/bash\n# Internal use only - DO NOT COMMIT\n# VTCH{d3l3t3d_n0t_g0n3_ext4_recovery}\nfor acct in $(cat targets.txt); do\n    ./post_adjustment \"$acct\" +5000000\ndone\n")
        
    with open(targets_path, "w") as f:
        f.write("5400110023\n5400110024\n5400110025\n")

    debugfs_script = [
        "mkdir home",
        "mkdir home/b.teller",
        "cd home/b.teller",
        f"write {bash_history_path} .bash_history",
        f"write {daily_report_path} daily_report.txt",
        f"write {adjust_script_path} adjust_balances.sh",
        f"write {targets_path} targets.txt",
        "rm adjust_balances.sh",
        "rm targets.txt",
        "close",
        "quit"
    ]
    
    cmd_debugfs = [DEBUGFS, "-w", IMG_PATH]
    res_debug = subprocess.run(
        cmd_debugfs,
        input="\n".join(debugfs_script),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    if res_debug.returncode != 0:
        print(f"[-] debugfs error: {res_debug.stderr}")
    else:
        print("[+] Filesystem populated and target files unlinked successfully.")

    # Cleanup temp directory
    for fname in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, fname))
    os.rmdir(temp_dir)

    print(f"[+] Challenge image created successfully: {IMG_PATH}")

if __name__ == "__main__":
    create_image()
