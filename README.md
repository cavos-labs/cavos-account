# cavos-account

[![Tests](https://github.com/cavos-labs/cavos-account/actions/workflows/test.yml/badge.svg)](https://github.com/cavos-labs/cavos-account/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cairo](https://img.shields.io/badge/Cairo-2.14.0-orange.svg)](https://docs.swmansion.com/scarb/)
[![Scarb](https://img.shields.io/badge/Scarb-2.14.0-purple.svg)](https://docs.swmansion.com/scarb/)
[![snforge](https://img.shields.io/badge/snforge-0.53.0-green.svg)](https://foundry-rs.github.io/starknet-foundry/)
[![Garaga](https://img.shields.io/badge/Garaga-RSA--2048-red.svg)](https://garaga.gitbook.io/garaga/using-garaga-libraries-in-your-cairo-project/rsa-signatures)
[![Starknet](https://img.shields.io/badge/StarkNet-Sepolia%20%7C%20Mainnet-black.svg)](https://starknet.io)

On-chain OAuth wallets on Starknet. Verify Google/Apple JWTs directly in a Cairo smart contract — no backend, no custodian.

## Overview

`cavos-account` implements an account contract (SRC-6) that authenticates users via OAuth JWTs instead of traditional private keys. The contract:

- Verifies RSA-2048 / SHA-256 JWT signatures on-chain using [Garaga](https://github.com/keep-starknet-strange/garaga)
- Ties ephemeral session keys to JWT nonces (Poseidon-based binding)
- Validates issuer (`iss`) and expiry (`exp`) claims from the signed JWT payload
- Enforces per-session spending policies (allowed contracts, call limits, time windows)
- Supports Google, Apple, and Firebase as identity providers

## Architecture

```
cavos_account.cairo   — Main SRC-6 account contract
jwks_registry.cairo   — Admin-controlled public key store
deployer.cairo        — Deterministic account deployment (address = f(iss, sub, salt))
jwt/
  base64.cairo        — Base64url decoder
  jwt_parser.cairo    — JWT claim parsing utilities
utils/
  address_seed.cairo  — Poseidon(iss, sub, salt) → deterministic address seed
  nonce.cairo         — Poseidon(eph_pubkey, max_block, randomness) → nonce
  base64url.cairo     — Re-exports
```

## Requirements

- [Scarb](https://docs.swmansion.com/scarb/) 2.14.0
- [starknet-foundry](https://foundry-rs.github.io/starknet-foundry/) 0.53.0+

## Getting Started

```bash
# Install Scarb
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install snforge
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh

# Build
scarb build

# Test
snforge test
```

## RSA-2048 Signature Verification

JWT signatures are verified on-chain using [Garaga's RSA-2048 implementation](https://garaga.gitbook.io/garaga/using-garaga-libraries-in-your-cairo-project/rsa-signatures#python) — an audited, ~11.8M gas verifier based on multi-precision arithmetic over RNS channels.

### Cairo contract usage

```cairo
use garaga::signatures::rsa::{
    RSA2048PublicKey, RSA2048SignatureWithHint,
    is_valid_rsa2048_sha256_signature,
};

// Construct public key from 24 × u96 limbs stored in JWKSKey
let public_key = RSA2048PublicKey { modulus: key.to_rsa2048_chunks() };

// Verify: internally computes SHA-256 + PKCS#1 v1.5 + s^65537 mod n
assert!(
    is_valid_rsa2048_sha256_signature(@sig_with_hint, @public_key, @jwt_signed_bytes),
    'Invalid JWT signature',
);
```

### Calldata generation (Python)

```python
from garaga.starknet.tests_and_calldata_generators.signatures import RSA2048Signature

sig = RSA2048Signature.from_sha256_message(jwt_signed_bytes, seed=0)
calldata = sig.serialize_sha256_with_hints(
    message=jwt_signed_bytes, prepend_public_key=False
)
# → 864 felt252 values: sig(24) + encoded_msg(24) + reductions(17×48)
```

### Calldata generation (TypeScript)

```typescript
import { rsa2048CalldataBuilder } from 'garaga';

const calldata = rsa2048CalldataBuilder(
    sigBigInt,          // RSA signature as bigint
    msgBytes,           // JWT header.payload as Uint8Array
    modulusBigInt,      // RSA modulus as bigint
    false               // don't prepend public key (already in registry)
);
// calldata.length === 864
```

### PKCS#1 v1.5 encoding

Garaga encodes the SHA-256 digest as:
```
0x00 || 0x01 || 0xFF×202 || 0x00 || DigestInfo(19 bytes) || SHA-256(32 bytes)
```
This is verified inside `is_valid_rsa2048_sha256_signature` — no manual encoding needed in the contract.

### JWKSKey format

Public keys are stored as 24 × `felt252` limbs (96-bit words, little-endian), matching Garaga's `RSA2048Chunks` layout:

```cairo
pub struct JWKSKey {
    pub n0: felt252,  pub n1: felt252,  // ...
    pub n23: felt252,
    pub provider: felt252, // same felt value as the JWT `iss` this key is allowed to verify
    pub valid_until: u64,
    pub is_active: bool,
}
```

Extract limbs from a PEM/JWK modulus (Python):
```python
mask = (1 << 96) - 1
limbs = [(n >> (96 * i)) & mask for i in range(24)]
```

---

## Session Key Flow

1. User authenticates with Google/Apple → receives JWT
2. SDK generates ephemeral key pair
3. Nonce = `Poseidon(eph_pubkey_lo, eph_pubkey_hi, max_block, randomness)` embedded in OAuth request
4. Contract verifies JWT signature against registered JWKS public key
5. Session key is bound to the account for `max_block` blocks

## Calldata Layout

```
[0]       Magic (OAUTH_JWT_V1)
[1]       ECDSA r
[2]       ECDSA s
[3]       Session public key
[4]       valid_until
[5]       randomness
[6]       jwt_sub
[7]       jwt_nonce
[8]       jwt_exp
[9]       jwt_kid (Poseidon hash of kid string)
[10]      jwt_iss (Poseidon hash of issuer string)
[11]      salt
[12]      wallet_name
[13-18]   Claim offsets (sub, nonce, kid positions in raw JWT)
[19]      Garaga RSA blob length (864)
[20-883]  RSA2048SignatureWithHint (sig×24 + msg×24 + 17×48 reductions)
[884]     JWT bytes length
[885+]    Packed JWT bytes (31-byte chunks)
[after]   Spending policy
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
