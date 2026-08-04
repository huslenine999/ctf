# Release Checklist

1. Build the Linux binary from this directory on this macOS workspace:

```sh
./build-linux.sh
```

2. Strip with LLVM if needed:

```sh
/opt/homebrew/opt/llvm/bin/llvm-strip tiny_vm
```

3. Confirm `file ../challenge/dist/tiny_vm` reports `ELF 64-bit LSB executable, x86-64, statically linked, stripped`.
4. Send only `challenge/dist/` to players.
