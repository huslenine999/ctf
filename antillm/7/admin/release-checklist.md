# Release Checklist

1. Run `../solution/solve.py` and confirm it prints the flag.
2. Run `python3 ../challenge/audit_blob.py '<flag>'` and confirm `accepted`.
3. Copy `../challenge/audit_blob.py` and the public README into
   `../challenge/dist/`.
4. Confirm `../challenge/dist/` contains no `admin/` or `solution/` files.
