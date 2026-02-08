{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.Sigma.DuplexSponge
--
-- The duplex sponge interface, as described in Section 3 ("The Duplex Sponge
-- Interface") of the
-- [Fiat-Shamir draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/#go.draft-irtf-cfrg-fiat-shamir.html).
--
-- A duplex sponge defines a stateful hash object that supports two operations:
-- absorb (which incrementally updates the internal hash state with input data)
-- and squeeze (which produces variable-length, unpredictable outputs). This
-- interface can be instantiated with various hash functions based on
-- permutation or compression functions (e.g. SHAKE128, Keccak-f[1600]).
--
-- The duplex sponge is a core building block of the Fiat-Shamir
-- transformation, which compiles an interactive sigma protocol into a
-- non-interactive one by replacing the verifier's random challenges with
-- hash outputs.
module Crypto.Sigma.DuplexSponge where

import Data.ByteString (ByteString)

-- | A duplex sponge, as defined in Section 3 of the
-- [Fiat-Shamir draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/#go.draft-irtf-cfrg-fiat-shamir.html).
--
-- The sponge operates over a base type ('Unit'), and supports absorbing
-- input and squeezing output in that type. Concrete instantiations include
-- byte-oriented sponges (where @'Unit' s = Word8@) such as SHAKE128 and
-- Keccak duplex sponges, as described in Section 8 ("Duplex Sponge
-- Interfaces") of the Fiat-Shamir draft.
class DuplexSponge s where
    -- | The base type over which the sponge operates. For byte-oriented
    -- sponges (SHAKE128, Keccak duplex sponge), this is a byte.
    type Unit s

    -- | Initialize a new duplex sponge from an initialization vector.
    --
    -- Corresponds to @new(iv: bytes) -> DuplexSponge@ in Section 3 of the
    -- Fiat-Shamir draft. The initialization vector is constructed as
    -- described in Section 5 ("Generation of the Initialization Vector").
    newDuplexSponge :: ByteString -> s

    -- | Absorb a list of units into the sponge, updating its internal state.
    --
    -- Corresponds to @absorb(self, values: list[Unit])@ in Section 3 of
    -- the Fiat-Shamir draft. The absorb operation incrementally updates the
    -- sponge's internal hash state.
    absorbDuplexSponge :: s -> [Unit s] -> s

    -- | Squeeze a given number of units from the sponge, producing
    -- unpredictable output and an updated sponge state.
    --
    -- Corresponds to @squeeze(self, length: int)@ in Section 3 of the
    -- Fiat-Shamir draft. The squeeze operation produces variable-length
    -- output that can be used as a digest, key stream, or verifier
    -- challenge material.
    squeezeDuplexSponge :: s -> Int -> ([Unit s], s)
