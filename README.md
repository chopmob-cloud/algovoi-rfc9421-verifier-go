# algovoi-rfc9421-verifier-go

A Go implementation of the AlgoVoi RFC 9421 (HTTP Message Signatures) plus
RFC 9530 (Content-Digest) verifier, laid out as TWO independent packages that
mirror the Python / TypeScript "pure add-on" architecture:

- `verifier/` (package `verifier`) is the core: Ed25519 verification, the
  public-key trust-boundary gate, signing-base construction, Signature-Input /
  Signature parsing, Content-Digest verification, and freshness / replay checks.
  It depends on nothing outside the Go standard library.
- `ecdsa/` (package `ecdsa`) is a SEPARATE add-on providing the RFC 9421
  `ecdsa-p256-sha256` and `ecdsa-p384-sha384` verifiers. It imports the core for
  the shared `VerifyError` family. The core NEVER imports the add-on.

This is a port of `algovoi-rfc9421-verifier` and `algovoi-rfc9421-ecdsa`. It
reproduces the reference signing-base bytes, the Ed25519 key gate decisions, and
the Ed25519 verification results byte-for-byte, validated against the frozen
cross-language reference vectors.

## Behaviour parity points

- Signing base (`verifier.BuildSigningBase`): per covered component emit
  `"<lowercased-name>": <value>`, newline-joined. `algovoi-v0` mode lowercases
  `@method` and appends no `@signature-params` line; `rfc9421` mode preserves
  `@method` as supplied and appends `"@signature-params": <params-block>`.
  `@authority` / `@scheme` are lowercased; `@path` / `@target-uri` are verbatim;
  `@status` is the integer as a string; unknown `@`-components error; headers are
  looked up case-insensitively.
- Parse (`verifier.ParseSignatureInput` / `ParseSignatureValue`): labelled and
  unlabelled forms; the Signature value must be canonical base64 (re-encoding must
  round-trip exactly), rejecting the pad-bit malleability class.
- Key gate (`verifier.CheckEd25519PublicKey`): rejects non-canonical (y >= p),
  off-curve, and small-order (`[8]P == identity`) Ed25519 public keys, fail-closed
  and before verification.
- ECDSA add-on: raw fixed-width `r||s` signatures (P-256 64 bytes, P-384 96
  bytes), point-on-curve validation, `r, s` in `[1, n-1]`, and optional strict
  low-s enforcement (off by default via `ecdsa.SetStrictLowS`).

## Build and test

```
go build ./...
go test ./...
```

The frozen-vector test reads
`C:/algo/algovoi-rfc9421-verifier-multilang/vectors/reference_vectors_v0.json`.
Override the location with the `ALGOVOI_REFERENCE_VECTORS` environment variable.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
