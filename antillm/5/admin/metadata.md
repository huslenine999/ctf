# Tiny VM

- Category: rev
- Difficulty: medium
- Estimated solve time: 45-90 minutes
- Flag: `VTCH{vm_handlers_define_truth!!}`
- Public files: `tiny_vm`, `README.md`
- Release binary: Linux x86_64 static ELF
- Release test: passed under Alpine Linux kernel in QEMU

## Notes

The intended path is to recover the VM handlers, decode the bytecode, and invert the per-byte transform.
The release binary includes extra dispatch/noise logic around the VM.
