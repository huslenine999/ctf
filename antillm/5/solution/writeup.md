# Technique 5 Writeup - tiny-vm

The binary contains a small VM. The bytecode is:

```text
LEN 32
LOAD
ADD_POS
XOR 0xa7
ROL_POS
CMP
NEXT
HALT
```

For each input byte at index `i`, the VM computes:

```text
rol8((input[i] + i * 17) ^ 0xa7, i)
```

Then it compares that value with the expected table.

Invert the operations in reverse order:

```text
input[i] = (ror8(expected[i], i) ^ 0xa7) - i * 17
```

Flag:

```text
VTCH{vm_handlers_define_truth!!}
```
