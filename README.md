# sigma-proofs

A Haskell implementation of zero-knowledge sigma protocols over prime-order
elliptic curve groups, following the IETF CFRG drafts:

- [Sigma Protocols draft](./draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.md)
- [Fiat-Shamir draft](./draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-fiat-shamir.md)

Sigma protocols are three-move interactive proofs of knowledge: a prover
commits to random nonces, receives a challenge, and responds in a way that
convinces the verifier of knowledge of a secret witness (e.g. a discrete
logarithm) without revealing it. The Fiat-Shamir transformation compiles
these interactive proofs into non-interactive ones by replacing the
verifier's challenge with the output of a hash function.

## Module overview

### Core abstractions

| Module | Description |
|---|---|
| `Crypto.Sigma.Scalar` | Type class for elements of a prime-order scalar field |
| `Crypto.Sigma.Group` | Type class for prime-order elliptic curve groups |
| `Crypto.Sigma.Random` | `MonadRandom` class abstracting over randomness sources (includes `IO` instance) |
| `Crypto.Sigma.DuplexSponge` | Type class for duplex sponge hash objects (absorb/squeeze) |
| `Crypto.Sigma.Error` | Shared `DeserializeError` type |

### Protocol logic

| Module | Description |
|---|---|
| `Crypto.Sigma.LinearMap` | Linear maps and relations over groups (sparse matrix representation) |
| `Crypto.Sigma.Protocol` | Interactive three-move sigma protocol (commit, challenge, respond) |
| `Crypto.Sigma.FiatShamir` | Non-interactive Fiat-Shamir proofs in compact and batchable formats |

### Concrete implementations (Ristretto255 via Rust FFI)

| Module | Description |
|---|---|
| `Crypto.Sigma.Curve25519.Ristretto255` | `Scalar` and `Group` instances for Ristretto255 |
| `Crypto.Sigma.Curve25519.FFI` | Raw foreign imports from the `sigma-ffi` Rust library |
| `Crypto.Sigma.Shake128` | SHAKE128 `DuplexSponge` instance via Rust FFI |
| `Crypto.Sigma.Keccak` | Keccak-f[1600] `DuplexSponge` instance via Rust FFI |

## Building

The library delegates all elliptic curve arithmetic and hash functions to a
companion Rust library (`rust/sigma-ffi/`). You will need:

- **GHC** (tested with 9.6.x)
- **Cabal** (>= 3.0)
- **Rust toolchain** (`cargo`, installed via [rustup](https://rustup.rs/))

The custom `Setup.hs` runs `cargo build --release` automatically before the
Haskell build, so a plain `cabal build` is sufficient:

```
cabal build
```

To run the test suite (includes cross-compatibility tests against the Rust
reference implementation):

```
cabal test
```

## Example: proving knowledge of a discrete logarithm

```haskell
import qualified Data.Vector as V
import Crypto.Sigma.Curve25519.Ristretto255
import Crypto.Sigma.FiatShamir
import Crypto.Sigma.Group
import Crypto.Sigma.Keccak
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
import Crypto.Sigma.Scalar

-- Build the relation: X = x * G
dlogProof :: Ristretto255Point -> SchnorrProof Ristretto255Point
dlogProof publicKey = newSchnorrProof $ buildLinearRelation_ $ do
  xIdx  <- allocateScalars 1   -- witness slot for the secret scalar x
  gIdx  <- allocateElements 1  -- slot for the generator G
  xIdx' <- allocateElements 1  -- slot for the public key X (image)
  setElements [ (V.head gIdx, groupGenerator)
              , (V.head xIdx', publicKey)
              ]
  appendEquation (V.head xIdx') [(V.head xIdx, V.head gIdx)]

main :: IO ()
main = do
  -- Prover: choose a secret scalar and compute the public key
  x <- scalarRandom :: IO Ristretto255Scalar
  let publicKey = groupGenerator |*| x
      proof     = dlogProof publicKey
      sponge    = makeIV "my-protocol" "" :: KeccakSponge
      witness   = V.singleton x

  -- Prove
  proofBytes <- prove sponge proof witness

  -- Verify
  case verify sponge proof proofBytes of
    Right True  -> putStrLn "Proof verified."
    Right False -> putStrLn "Proof rejected."
    Left err    -> print err
```
