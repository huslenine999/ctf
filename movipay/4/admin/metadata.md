# MoviPay 4 - Roaming Bypass

- Category: pwn / protocol
- Difficulty: medium
- Estimated solve time: 45-90 minutes
- Flag: `VeriTransit{r0am1ng_1d3nt1ty_n0t_r3b0und_t0_s3ss10n}`
- Public files: `roam_client`, `capture.txt`, `README.md`
- Service files: `server.py`, `Dockerfile`
- Intended technique: TLV protocol reversing, HMAC credential recovery, session/account binding flaw

## Design Notes

The reference client authenticates as `EVU-1001` using a short HMAC proof derived
from constants hidden by small XOR decoders. The server correctly verifies the
authenticated client during `AUTH`, but later trusts the independent account ID
provided by `START`.

The intended solve authenticates normally as `EVU-1001`, then starts settlement
against the internal zero-rate account `0000-PLATFORM`.

For competition deployment, do not publish `server.py`, `admin/`, `solution/`,
or the private client source. Release only `challenge/dist/`.
