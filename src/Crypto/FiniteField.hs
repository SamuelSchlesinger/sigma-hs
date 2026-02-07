{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Crypto.FiniteField
--
-- The scalar field interface, as described in the "Scalar" subsection of
-- Section 4.1 ("Group abstraction") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- Scalars are elements of the finite field associated with a prime-order
-- group. They support field addition, field multiplication, and
-- serialization to and from canonical byte representations. Scalars serve
-- as witnesses in sigma protocols and as the domain of linear maps.
module Crypto.FiniteField
  ( Scalar(..)
  , DeserializeError(..)
  ) where

import Data.ByteString (ByteString)
import Data.Proxy (Proxy)

data DeserializeError = DeserializeError String
  deriving (Show, Eq)

-- | An element of the scalar field associated with a prime-order group,
-- as defined in the "Scalar" subsection of Section 4.1 ("Group abstraction")
-- of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- Instances must satisfy the field laws: 'scalarAdd' and 'scalarMul' are
-- associative and commutative, 'scalarIdentity' is the additive identity,
-- and multiplication distributes over addition.
class Eq s => Scalar s where
  -- | The additive identity element in the scalar field.
  --
  -- Corresponds to @identity()@ in the spec.
  scalarIdentity :: s

  -- | Field addition.
  --
  -- Corresponds to @add(scalar: Scalar)@ in the spec (written as @+@ with
  -- infix notation).
  scalarAdd :: s -> s -> s

  -- | Field multiplication.
  --
  -- Corresponds to @mul(scalar: Scalar)@ in the spec (written as @*@ with
  -- infix notation).
  scalarMul :: s -> s -> s

  -- | Returns an element sampled uniformly at random from the scalar field.
  --
  -- Corresponds to @random()@ in the spec.
  scalarRandom :: IO s

  -- | Size in bytes of a single serialized scalar.
  --
  -- Corresponds to @Ns@ in the spec.
  scalarSize :: Proxy s -> Int

  -- | Serialize a scalar to its canonical byte representation.
  --
  -- Corresponds to @serialize(scalars: list[Scalar; N])@ in the spec,
  -- specialized to a single scalar.
  serializeScalar :: s -> ByteString

  -- | Deserialize a scalar from its canonical byte representation.
  -- Returns a 'DeserializeError' if the input is not a valid canonical
  -- encoding.
  --
  -- Corresponds to @deserialize(buffer)@ in the spec, specialized to a
  -- single scalar.
  deserializeScalar :: ByteString -> Either DeserializeError s
