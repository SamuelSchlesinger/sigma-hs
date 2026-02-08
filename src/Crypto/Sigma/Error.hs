-- |
-- Module: Crypto.Sigma.Error
--
-- Shared error types for deserialization across the sigma protocol library.
module Crypto.Sigma.Error
  ( DeserializeError(..)
  ) where

-- | An error encountered when deserializing a scalar or group element
-- from its byte representation.
data DeserializeError = DeserializeError String
  deriving (Show, Eq)
