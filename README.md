# cavos-account

On-chain OAuth wallets on Starknet. Verify Google/Apple JWTs directly in a Cairo smart contract — no backend, no custodian.

## Overview

`cavos-account` implements an account contract (SRC-6) that authenticates users via OAuth JWTs instead of traditional private keys. The contract:

- Verifies RSA-2048 / SHA-256 JWT signatures on-chain using [Garaga](https://github.com/keep-starknet-strange/garaga)
- Ties ephemeral session keys to JWT nonces (Poseidon-based binding)
- Validates issuer (`iss`) and audience (`aud`) claims against a JWKS registry
- Enforces per-session spending policies (allowed contracts, call limits, time windows)
- Supports Google, Apple, and Firebase as identity providers

## Architecture

```
cavos_account.cairo   — Main SRC-6 account contract
jwks_registry.cairo   — Admin-controlled public key store
deployer.cairo        — Deterministic account deployment (address = f(sub, salt))
jwt/
  base64.cairo        — Base64url decoder
  jwt_parser.cairo    — JWT claim parsing utilities
utils/
  address_seed.cairo  — Poseidon(sub, salt) → deterministic address seed
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
