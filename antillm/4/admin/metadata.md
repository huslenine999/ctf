# Tea Party

- Category: rev/crypto
- Difficulty: medium
- Estimated solve time: 30-60 minutes
- Flag: `VeriTransit{tweaked_tea_add_rn!}`
- Public files: `tea_party`, `README.md`
- Release binary: Linux x86_64 static ELF
- Release test: passed under Alpine Linux kernel in QEMU

## Notes

The binary resembles TEA but changes the round expression. Solvers must inspect or emulate the exact implementation.
The release binary includes extra opaque/noise logic around the core check.
