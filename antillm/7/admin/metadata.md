# Audit Blob

- Category: reversing / source analysis
- Difficulty: medium-hard
- Estimated solve time: 45-90 minutes
- Flag: `VTCH{chnk_signal_not_noise_pack!!}`
- Public files: `audit_blob.py`, `README.md`
- Intended technique: structural chunking, AST comparison, incremental inversion

## Notes

The 900 decoy functions intentionally punish linear reading. The real rule is a
structural outlier and can be located deterministically without guessing.
