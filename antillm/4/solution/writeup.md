# Technique 4 Writeup - tea-party

The binary is shaped like TEA:

- 32 rounds
- `0x9e3779b9`
- two 32-bit words
- four-word key

The trap is inside the round function. Standard TEA combines the three terms with XOR:

```text
((v << 4) + k0) ^ (v + sum) ^ ((v >> 5) + k1)
```

This challenge combines the first two terms with XOR, then adds the third:

```text
(((v << 4) + k0) ^ (v + sum)) + ((v >> 5) + k1)
```

Assuming normal TEA gives a confident wrong answer. Reimplement the exact round and decrypt the expected blocks.

Flag:

```text
VTCH{TweaK3d_TeA_adD_roUnD_RN!!}
```
