# Solution Writeup: PyJail AST Sandbox (`misc/pyjail`)

## Vulnerability & Bypass Breakdown

1. **AST & String Blacklist**:
   The sandbox blocks `import` statements, `exec`/`eval`, and blacklists raw string keywords (`"open"`, `"import"`, `"os"`, `"sys"`, `"flag"`, etc.).

2. **Attribute Concatenation**:
   Because string concatenation (`'o'+'p'+'e'+'n'`, `'f'+'lag.txt'`, `'__sub'+'classes__'`) is valid AST and not matched by literal string search, we can dynamically build forbidden attribute names.

3. **Reflection & Globals Extraction**:
   Accessing `object` via `getattr(type(()), '__ba'+'se__')` allows querying all loaded subclasses via `__subclasses__()`. Iterating over these subclasses to locate any class whose `__init__` function holds a `__globals__` dict grants access to Python's module global environment and `__builtins__`.

4. **Flag Extraction**:
   From `__builtins__`, we retrieve the original `open` handle to read `flag.txt`.

## Running Solution
```sh
python3 misc/pyjail/1/solution/solve.py <HOST> 31339
```
