# Challenge 1: Cleared Logs

| Attribute | Details |
| :--- | :--- |
| **Title** | Cleared Logs |
| **Category** | Disk Forensics / File Recovery |
| **Difficulty** | Easy |
| **Suggested Points** | 100 |
| **Files Provided** | `teller_ws.img` (ext4 partition image, ~300 MB) |
| **Flag** | `FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}` |

---

## 1. Challenge Description

### Player-Facing Scenario
A teller at a branch office is suspected of running an unauthorized balance-adjustment script and then deleting it to hide the evidence. Internal Audit has imaged the employee's workstation partition. Recover what was deleted and find the proof.

### Narrative Hook
The script ran once during the lunch hour, posted several adjustments, and was removed minutes later. The filesystem has not been heavily written since, so the data blocks should still be recoverable.

### Learning Objective
Teach competitors that deletion on a journaling filesystem (ext4) does not immediately destroy file content, and introduce standard inode/file recovery tooling (`debugfs`, `extundelete`, `foremost`, or raw carving).

---

## 2. Intended Solution Method

1. **Identify the Filesystem**:
   Run `file teller_ws.img` or inspect partition headers to confirm it is an `ext4` filesystem.
   ```bash
   $ file teller_ws.img
   teller_ws.img: Linux rev 1.0 ext4 filesystem data, volume name "TELLER_WS"...
   ```

2. **Method A: Inode Recovery via `debugfs`**:
   Open `debugfs` on the disk image:
   ```bash
   $ debugfs -R 'lsdel' teller_ws.img
   Inode  Owner  Mode    Size      Blocks   Time deleted
      17      0 100644    166      1/     1 Thu Aug  6 10:01:55 2026
      18      0 100644     33      1/     1 Thu Aug  6 10:01:55 2026
   ```
   Dump deleted inode 17 content:
   ```bash
   $ debugfs -R 'dump <17> recovered_script.sh' teller_ws.img
   $ cat recovered_script.sh
   #!/bin/bash
   # Internal use only - DO NOT COMMIT
   # FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}
   for acct in $(cat targets.txt); do
       ./post_adjustment "$acct" +5000000
   done
   ```

3. **Method B: Automatic Restoration via `extundelete`**:
   ```bash
   $ extundelete teller_ws.img --restore-all
   $ cat RECOVERED_FILES/home/b.teller/adjust_balances.sh
   ```

4. **Method C: String Scanning / Carving**:
   Since deletion on ext4 zero-fills directory entries but retains unallocated block data:
   ```bash
   $ strings teller_ws.img | grep FLAG{
   # FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}
   ```

---

## 3. Build & Generation Guide

The disk image can be generated reproducibly using the included `build.py` script:

```bash
python3 build.py
```

### Manual Linux Commands (Alternative Build Method)
```bash
# 1. Create partition image
dd if=/dev/zero of=teller_ws.img bs=1M count=300
mkfs.ext4 -L TELLER_WS teller_ws.img

# 2. Mount image
mkdir -p /mnt/ctf && sudo mount -o loop teller_ws.img /mnt/ctf

# 3. Populate home directory
sudo mkdir -p /mnt/ctf/home/b.teller
cd /mnt/ctf/home/b.teller

sudo tee .bash_history >/dev/null <<'EOF'
ls -la
cat daily_report.txt
./post_adjustment --help
rm adjust_balances.sh targets.txt
history -c
EOF

sudo tee daily_report.txt >/dev/null <<'EOF'
TELLER DAILY REPORT - BRANCH #402
Date: 2026-08-05
Status: All registers balanced at 17:00.
No anomalies reported during shift.
EOF

# 4. Plant script containing flag, then delete
sudo tee adjust_balances.sh >/dev/null <<'EOF'
#!/bin/bash
# Internal use only - DO NOT COMMIT
# FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}
for acct in $(cat targets.txt); do
    ./post_adjustment "$acct" +5000000
done
EOF

printf '5400110023\n5400110024\n5400110025\n' | sudo tee targets.txt
sync

# 5. Remove files & unmount
sudo rm adjust_balances.sh targets.txt
sync
cd / && sudo umount /mnt/ctf
```

---

## 4. Verification

Run the included verification script:
```bash
python3 solve.py
```
Expected output:
```
SUCCESS: Flag correctly recovered: FLAG{d3l3t3d_n0t_g0n3_ext4_recovery}
```

---

## 5. Hints & Scoring

- **Tier 1 Hint**: "The file is gone from the listing, but is it gone from the disk? Check what type of filesystem this is." *(Deduct 10 pts)*
- **Tier 2 Hint**: "Use tools designed for ext4 inode recovery such as `debugfs` or `extundelete`." *(Deduct 20 pts)*
- **Tier 3 Hint**: "Query deleted inodes using `debugfs -R 'lsdel' teller_ws.img` or grep disk strings for `FLAG{`." *(Deduct 30 pts)*
