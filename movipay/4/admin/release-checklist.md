# Release Checklist

- Build the public Linux reference client: `./build-public-binary.sh`.
- Build the local host-native reference client only if needed:
  `cd ../challenge && ./build.sh`.
- Public attachment should contain only `challenge/dist/`.
- Confirm `challenge/dist/` contains `README.md`, `roam_client`, and
  `capture.txt`.
- Do not include `server.py`, `flag.txt`, `admin/`, `solution/`, build outputs,
  client source, headers, or this checklist in public files.
- Run with the real flag injected by environment:
  `cd challenge && PORT=31336 FLAG="$(cat ../admin/flag.txt)" python3 server.py`.
- For container deployment, build from `challenge/` and keep `HOST=0.0.0.0`.
- Smoke test against the deployed service:
  `python3 solution/solve.py 127.0.0.1 31336`.
