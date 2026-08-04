# MoviPay 4 - Roaming Bypass

## Protocol

Frames use:

```text
"MV" | version:u8 | type:u8 | payload_len:u16be | payload
```

The payload is a sequence of TLVs:

```text
tag:u8 | len:u8 | value
```

The normal flow is:

```text
HELLO -> CHALLENGE -> AUTH -> START -> SETTLE
```

Important tags:

```text
0x01 CLIENT_ID
0x02 NONCE
0x03 HMAC
0x04 ACCOUNT_ID
0x07 SESSION
```

## Reversing

The reference client has two tiny XOR decoders:

```text
encrypted_identity ^ 0x22 = EVU-1001
encrypted_key      ^ 0x42 = ROAM_KEY_SECRET
```

The packet code and the capture show that authentication is:

```text
HMAC-SHA256(ROAM_KEY_SECRET, CLIENT_ID || nonce)[:8]
```

This proves possession of the roaming key for `EVU-1001`.

## Bug

The server authenticates `client_id` during `AUTH`, but later trusts the
independent `ACCOUNT_ID` sent in `START`.

The reference client always sends:

```text
CLIENT_ID=EVU-1001
ACCOUNT_ID=EVU-1001
```

The server never checks that `START.ACCOUNT_ID` still belongs to the
authenticated identity.

## Exploit

Authenticate normally as `EVU-1001`, then start the session with the internal
zero-rate account:

```text
ACCOUNT_ID=0000-PLATFORM
```

Settlement returns:

```text
VTCH{r0am1ng_1d3nt1ty_n0t_r3b0und_t0_s3ss10n}
```
