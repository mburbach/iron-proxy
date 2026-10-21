Public certificate chains from https://emudhra.we-have-a-problem.com/chains.zip
Source: https://github.com/galadran/we-have-a-problem.com/tree/main/chains
Retrieved 2026-10-21. These fixtures contain public certificates only.

The twelve chains cover the six compromised TLS CA keys, each through its
emSign issuer and its AAA Certificate Services cross-sign. Tests deliberately
trust the last supplied certificate to exercise Go's key-based rejection even
with custom roots, independently of host trust-store updates. Verification uses
a fixed time within the leaf validity period so expiry cannot mask regressions.
