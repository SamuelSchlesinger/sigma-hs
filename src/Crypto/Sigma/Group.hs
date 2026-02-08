{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.Sigma.Group
--
-- The prime-order elliptic curve group interface, as described in the /Group/
-- subsection of Section 4.1 ("Group abstraction") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- A prime-order group provides the algebraic setting in which sigma protocols
-- operate. Group elements can be added, multiplied by scalars from the
-- associated scalar field, and serialized to and from canonical byte
-- representations.
module Crypto.Sigma.Group
  ( Group(..)
  , (|+|)
  , (|-|)
  , (|*|)
  ) where

import Data.ByteString (ByteString)
import qualified Data.Vector as V

import Crypto.Sigma.Error (DeserializeError)
import Crypto.Sigma.Random (MonadRandom)
import Crypto.Sigma.Scalar (Scalar)

-- | A prime-order elliptic curve group, as defined in the /Group/ subsection
-- of Section 4.1 ("Group abstraction") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- Instances must satisfy the usual group laws: 'groupAdd' is associative
-- with 'groupIdentity' as the neutral element, and 'groupGenerator'
-- generates the full prime-order subgroup. The 'Eq' constraint corresponds
-- to the @equal(element: Group)@ operation in the spec.
class (Eq g, Scalar (GroupScalar g)) => Group g where
  -- | The scalar field associated with this group.
  --
  -- Corresponds to @Group.ScalarField@ in the spec.
  type GroupScalar g

  -- | The neutral (identity) element in the group.
  --
  -- Corresponds to @identity()@ in the spec.
  groupIdentity :: g

  -- | The generator of the prime-order elliptic-curve subgroup used for
  -- cryptographic operations.
  --
  -- Corresponds to @generator()@ in the spec.
  groupGenerator :: g

  -- | The order of the group.
  --
  -- Corresponds to @order()@ in the spec, which returns the prime order
  -- @p@ of the group.
  groupOrder :: Integer

  -- | Returns an element sampled uniformly at random from the group.
  --
  -- Corresponds to @random()@ in the spec.
  groupRandom :: MonadRandom m => m g

  -- | Elliptic curve addition of two group elements.
  --
  -- Corresponds to @add(element: Group)@ in the spec (written as @+@ with
  -- infix notation).
  groupAdd :: g -> g -> g

  -- | Additive inverse of a group element.
  groupNeg :: g -> g

  -- | Group subtraction.
  --
  -- Default: @groupSub a b = groupAdd a (groupNeg b)@
  groupSub :: g -> g -> g
  groupSub a b = groupAdd a (groupNeg b)

  -- | Scalar multiplication of a group element by an element in its
  -- respective scalar field.
  --
  -- Corresponds to @scalar_mul(scalar: Scalar)@ in the spec (written as
  -- @*@ with infix notation).
  groupScalarMul :: g -> GroupScalar g -> g

  -- | Multi-scalar multiplication. Computes the sum of element-scalar
  -- products: @sum_i (elements[i] * scalars[i])@.
  --
  -- The default implementation performs the naive pairwise multiply-and-add.
  -- Instances may override with optimized algorithms (e.g. Pippenger).
  msm :: V.Vector (GroupScalar g) -> V.Vector g -> g
  msm scalars elements =
    V.foldl' groupAdd groupIdentity (V.zipWith (flip groupScalarMul) scalars elements)

  -- | Size in bytes of a single serialized group element.
  --
  -- Corresponds to @Ne@ in the spec.
  elementSize :: Int

  -- | Serialize a group element to its canonical byte representation.
  --
  -- Corresponds to @serialize(elements: [Group; N])@ in the spec,
  -- specialized to a single element.
  serializeElement :: g -> ByteString

  -- | Deserialize a group element from its canonical byte representation.
  -- Returns a 'DeserializeError' if the input is not a valid canonical
  -- encoding.
  --
  -- Corresponds to @deserialize(buffer)@ in the spec, specialized to a
  -- single element.
  deserializeElement :: ByteString -> Either DeserializeError g

infixl 6 |+|
-- | Group addition. Synonym for 'groupAdd'.
(|+|) :: Group g => g -> g -> g
(|+|) = groupAdd

infixl 6 |-|
-- | Group subtraction. Synonym for 'groupSub'.
(|-|) :: Group g => g -> g -> g
(|-|) = groupSub

infixl 7 |*|
-- | Scalar multiplication. Synonym for 'groupScalarMul'.
(|*|) :: Group g => g -> GroupScalar g -> g
(|*|) = groupScalarMul
