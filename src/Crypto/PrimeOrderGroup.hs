{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.PrimeOrderGroup
  ( Group(..)
  ) where

import Data.ByteString (ByteString)
import Data.Proxy (Proxy)

import Crypto.FiniteField (Scalar, DeserializeError)

class (Eq g, Scalar (GroupScalar g)) => Group g where
  -- | The scalar field associated with this group.
  type GroupScalar g

  -- | The neutral (identity) element in the group.
  groupIdentity :: g

  -- | The generator of the prime-order elliptic-curve subgroup.
  groupGenerator :: g

  -- | The order of the group.
  groupOrder :: Proxy g -> Integer

  -- | Returns an element sampled uniformly at random from the group.
  groupRandom :: IO g

  -- | Elliptic curve addition of two group elements.
  groupAdd :: g -> g -> g

  -- | Scalar multiplication of a group element by a scalar field element.
  groupScalarMul :: g -> GroupScalar g -> g

  -- | Size in bytes of a single serialized group element.
  elementSize :: Proxy g -> Int

  -- | Serialize a group element to its canonical byte representation.
  serializeElement :: g -> ByteString

  -- | Deserialize a group element from its canonical byte representation.
  deserializeElement :: ByteString -> Either DeserializeError g
