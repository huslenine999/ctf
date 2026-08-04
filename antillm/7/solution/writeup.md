# Technique 7 Writeup - Audit Blob

The verifier is designed to consume analysis context: it contains 900 similarly
named audit functions and a large policy matrix. Almost every rule has the same
four-integer checksum template, so reading functions one by one is a trap.

Structural analysis of the Python AST reveals one outlier, `audit_rule_0731`.
Its `reference` list has 34 entries and it checks every byte immediately:

```python
acc = ((acc * 33) ^ ch ^ i) & 0xff
((ch + acc + i * 7) & 0xff) == reference[i]
```

Start with `acc = 0x5a`. For each position, try printable byte values, retain
those satisfying the current reference byte, and carry the resulting accumulator
to the next position. The required final accumulator (`43`) leaves one candidate.

Flag:

```text
VTCH{chnk_signal_not_noise_pack!!}
```

The key lesson is to compare structure and isolate the anomalous rule instead of
spending time or model context on hundreds of decoys.
