{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module: Crypto.Sigma.Curve25519.Random
--
-- 'MonadRandom' instance for 'IO' using the OS CSPRNG via Rust FFI.
module Crypto.Sigma.Curve25519.Random () where

import qualified Data.ByteString.Internal as BSI
import Foreign.ForeignPtr (withForeignPtr, mallocForeignPtrBytes)

import Crypto.Sigma.Random (MonadRandom(..))
import Crypto.Sigma.Curve25519.FFI (sigma_random_bytes)

instance MonadRandom IO where
  getRandomBytes n = do
    fp <- mallocForeignPtrBytes n
    withForeignPtr fp $ \p ->
      sigma_random_bytes p (fromIntegral n)
    return (BSI.BS fp n)
