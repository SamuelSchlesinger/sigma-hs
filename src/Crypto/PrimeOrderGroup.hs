{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.PrimeOrderGroup
--
-- The prime-order elliptic curve group interface, as described in the "Group"
-- subsection of Section 4.1 ("Group abstraction") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- A prime-order group provides the algebraic setting in which sigma protocols
-- operate. Group elements can be added, multiplied by scalars from the
-- associated scalar field, and serialized to and from canonical byte
-- representations.
module Crypto.PrimeOrderGroup
  ( Group(..)
  ) where

import Data.ByteString (ByteString)
import Data.Proxy (Proxy)

import Crypto.FiniteField (Scalar, DeserializeError)

-- | A prime-order elliptic curve group, as defined in the "Group" subsection
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
  groupOrder :: Proxy g -> Integer

  -- | Returns an element sampled uniformly at random from the group.
  --
  -- Corresponds to @random()@ in the spec.
  groupRandom :: IO g

  -- | Elliptic curve addition of two group elements.
  --
  -- Corresponds to @add(element: Group)@ in the spec (written as @+@ with
  -- infix notation).
  groupAdd :: g -> g -> g

  -- | Scalar multiplication of a group element by an element in its
  -- respective scalar field.
  --
  -- Corresponds to @scalar_mul(scalar: Scalar)@ in the spec (written as
  -- @*@ with infix notation).
  groupScalarMul :: g -> GroupScalar g -> g

  -- | Size in bytes of a single serialized group element.
  --
  -- Corresponds to @Ne@ in the spec.
  elementSize :: Proxy g -> Int

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
