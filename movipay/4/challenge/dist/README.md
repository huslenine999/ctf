# MoviPay 4 - Roaming Bypass

A roaming settlement hub speaks a proprietary binary TLV protocol over TCP.

Provided files:

- `roam_client`: Linux x86_64 reference client
- `capture.txt`: one normal authenticated settlement session

Connect to the challenge service at the host and port supplied by the organizers. The normal client authenticates as `EVU-1001` and settles against the same account; find a way to make the server settle against the internal zero-rate account instead.
