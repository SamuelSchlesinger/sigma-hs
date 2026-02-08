{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Crypto.Sigma.Scalar
--
-- The scalar field interface, as described in the "Scalar" subsection of
-- Section 4.1 ("Group abstraction") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- Scalars are elements of the finite field associated with a prime-order
-- group. They support field addition, field multiplication, and
-- serialization to and from canonical byte representations. Scalars serve
-- as witnesses in sigma protocols and as the domain of linear maps.
module Crypto.Sigma.Scalar
  ( Scalar(..)
  , (.+.)
  , (.-.)
  , (.*.)
  ) where

import Data.ByteString (ByteString)

import Crypto.Sigma.Error (DeserializeError)
import Crypto.Sigma.Random (MonadRandom)

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

  -- | Additive inverse in the scalar field.
  scalarNeg :: s -> s

  -- | Field subtraction.
  --
  -- Default: @scalarSub a b = scalarAdd a (scalarNeg b)@
  scalarSub :: s -> s -> s
  scalarSub a b = scalarAdd a (scalarNeg b)

  -- | Returns an element sampled uniformly at random from the scalar field.
  --
  -- Corresponds to @random()@ in the spec.
  scalarRandom :: MonadRandom m => m s

  -- | Size in bytes of a single serialized scalar.
  --
  -- Corresponds to @Ns@ in the spec.
  scalarSize :: Int

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

  -- | Reduce uniform bytes to a scalar. Input should be at least
  -- @scalarSize + 16@ bytes for near-uniform distribution.
  scalarFromUniformBytes :: ByteString -> s

infixl 6 .+.
-- | Scalar field addition. Synonym for 'scalarAdd'.
(.+.) :: Scalar s => s -> s -> s
(.+.) = scalarAdd

infixl 6 .-.
-- | Scalar field subtraction. Synonym for 'scalarSub'.
(.-.) :: Scalar s => s -> s -> s
(.-.) = scalarSub

infixl 7 .*.
-- | Scalar field multiplication. Synonym for 'scalarMul'.
(.*.) :: Scalar s => s -> s -> s
(.*.) = scalarMul
