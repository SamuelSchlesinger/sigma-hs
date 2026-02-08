-- |
-- Module: Crypto.Sigma.Error
--
-- Shared error types for deserialization across the sigma protocol library.
module Crypto.Sigma.Error
  ( DeserializeError(..)
  ) where

data DeserializeError = DeserializeError String
  deriving (Show, Eq)
