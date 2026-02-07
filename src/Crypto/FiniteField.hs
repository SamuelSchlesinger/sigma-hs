{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.FiniteField
  ( Scalar(..)
  , DeserializeError(..)
  ) where

import Data.ByteString (ByteString)
import Data.Proxy (Proxy)

data DeserializeError = DeserializeError String
  deriving (Show, Eq)

class Eq s => Scalar s where
  -- | The additive identity element in the scalar field.
  scalarIdentity :: s

  -- | Field addition.
  scalarAdd :: s -> s -> s

  -- | Field multiplication.
  scalarMul :: s -> s -> s

  -- | Returns an element sampled uniformly at random from the scalar field.
  scalarRandom :: IO s

  -- | Size in bytes of a single serialized scalar.
  scalarSize :: Proxy s -> Int

  -- | Serialize a scalar to its canonical byte representation.
  serializeScalar :: s -> ByteString

  -- | Deserialize a scalar from its canonical byte representation.
  deserializeScalar :: ByteString -> Either DeserializeError s
