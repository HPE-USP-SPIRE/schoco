# SchoCo: Schnorr Signature Concatenation

SchoCo is a Go implementation of a Schnorr-based half-aggregate signature scheme designed for extensible tokens. It enables sequential authentication of messages, allowing a holder to extend an authenticated sequence without access to the original signer's private key.

The construction and its security properties are described in:

**SchoCo: Schnorr signature concatenation for extensible tokens**  
*Journal of Information Security and Applications*, Volume 97, 2026.  
https://doi.org/10.1016/j.jisa.2025.104327

## Features

- Schnorr-based digital signatures.
- Sequential signature aggregation and verification.
- Token continuation without access to the original signing key.
- Go implementation with correctness tests and benchmarks.
- Application-specific helpers for PACT/SACT integration.

## Installation

```bash
go get github.com/hpe-usp-spire/schoco
```

## API

The package provides the following core operations:

- `KeyPair`: generate a signing key pair.
- `StdSign` and `StdVerify`: sign and verify individual messages.
- `Aggregate`: extend an existing signature with a new message.
- `Verify`: verify an authenticated sequence of messages.
- `MarshalBinary` and `UnmarshalSignature`: serialize and deserialize signatures.

The package also includes PACT-specific wrappers (`PACTSlotMessage`, `StdSignPACT`, `AggregatePACT`, and `VerifyPACT`) that bind authorization prefixes to explicit signature positions. These are application-specific helpers; the core SchoCo API operates on arbitrary messages.

## Tests and Benchmarks

Run the test suite:

```bash
go test ./...
```

Run benchmarks:

```bash
go test -run '^$' -bench . -benchmem ./...
```

## Research Prototype

This implementation is intended for research and experimental evaluation. It has not been independently audited for production deployment.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Third-party dependencies retain their respective licenses.
