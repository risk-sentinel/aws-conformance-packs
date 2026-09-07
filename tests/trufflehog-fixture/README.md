# TruffleHog fixture

Synthetic, non-functional credential used ONLY to prove the secret scanner
still fires. If `secret-scan.yml`'s fixture-detection job stops failing here,
the scanner has regressed and the real gate is silently doing nothing.

Nothing in this directory is a real credential. It is excluded from the
verified-secrets gate via `.trufflehog-exclude-paths`.
