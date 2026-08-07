#!/usr/bin/env python3
"""
KhanCTF - PyJail AST Sandbox Service
Port: 31339
"""

import ast
import os
import sys
import socketserver

FLAG = os.environ.get("FLAG", "VTCH{4st_w4lker_c4nt_st0p_th3_d4rk_dund3rs!!}")

BANNED_WORDS = [
    "import", "open", "os", "sys", "subprocess",
    "flag", "eval", "exec", "system"
]

class ASTChecker(ast.NodeVisitor):
    def visit_Import(self, node):
        raise ValueError("Import statement disabled.")

    def visit_ImportFrom(self, node):
        raise ValueError("ImportFrom statement disabled.")

    def visit_Exec(self, node):
        raise ValueError("Exec statement disabled.")


def sanitize_code(code: str):
    if len(code) > 400:
        raise ValueError("Payload too long (max 400 chars).")

    code_lower = code.lower()
    for word in BANNED_WORDS:
        if word in code_lower:
            raise ValueError(f"Forbidden word detected: '{word}'")

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise ValueError(f"Syntax error: {e}")

    checker = ASTChecker()
    checker.visit(tree)
    return tree


def run_jail(user_code: str) -> str:
    sanitize_code(user_code)

    output_lines = []
    def custom_print(*args, **kwargs):
        output_lines.append(" ".join(str(a) for a in args))

    safe_builtins = {
        "print": custom_print,
        "range": range,
        "len": len,
        "ord": ord,
        "chr": chr,
        "str": str,
        "int": int,
        "type": type,
        "list": list,
        "dict": dict,
        "tuple": tuple,
        "getattr": getattr,
        "hasattr": hasattr,
        "dir": dir,
    }

    local_scope = {}
    global_scope = {"__builtins__": safe_builtins}

    exec(user_code, global_scope, local_scope)
    return "\n".join(output_lines) if output_lines else "[+] Code executed successfully."


class JailTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"=== Welcome to KhanCTF PyJail Sandbox ===\n")
        self.wfile.write(b"Enter your Python code (one line, max 400 chars):\n> ")
        self.wfile.flush()

        line = self.rfile.readline()
        if not line:
            return

        user_code = line.decode('utf-8', errors='ignore').strip()
        try:
            res = run_jail(user_code)
            self.wfile.write(f"{res}\n".encode('utf-8'))
        except Exception as e:
            self.wfile.write(f"[-] Error: {e}\n".encode('utf-8'))
        self.wfile.flush()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "31339"))

    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "w") as f:
        f.write(FLAG + "\n")

    print(f"[*] PyJail Sandbox listening on {host}:{port}")
    server = ThreadedTCPServer((host, port), JailTCPHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
