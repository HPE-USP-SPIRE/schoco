# SchoCo: Schnorr Signature Concatenation Scheme

This Go package implements the SchoCo scheme, an extension of the Schnorr digital signature that supports signature concatenation.  
It enables efficient aggregation of multiple signatures, making it suitable for applications requiring compact and verifiable multi-signature schemes.

## Features

- Schnorr digital signature implementation
- Support for signature concatenation (SchoCo)
- Benchmarking tools for performance evaluation
- Comprehensive test suite

## Installation

To include `schoco` in your Go project:

```bash
go get github.com/HPE-USP-SPIRE/schoco
```

## Usage  

Import the package in your Go code:

```
import "github.com/HPE-USP-SPIRE/schoco"
```

## Run Tests  

```
go test -v
```

## Run Benchmarks

```
go test -bench=Benchmark -benchmem
```

## Details

⚠️ This project is a **PROOF OF CONCEPT** and is provided without any warranties or guarantees. Use at your own risk.  

The package is a  provides functions for key generation, signing, verification, and signature concatenation.

Additional details are available in the source code.  




