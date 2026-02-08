-- |
-- Module: Crypto.Sigma.Random
--
-- A minimal random byte generation interface for cryptographic operations.
--
-- This abstracts over the source of randomness so that sigma protocol
-- operations (e.g. generating nonces, sampling random scalars) are not
-- tied to 'IO'. Concrete instances can use a system CSPRNG, a
-- deterministic PRNG for testing, or any other byte source.
--
-- An 'IO' instance is provided that delegates to the OS CSPRNG via
-- the @entropy@ package.
module Crypto.Sigma.Random
  ( MonadRandom(..)
  ) where

import Data.ByteString (ByteString)
import System.Entropy (getEntropy)

-- | A monad that can generate random bytes.
class Monad m => MonadRandom m where
  -- | Generate a 'ByteString' of the given length filled with random bytes.
  getRandomBytes :: Int -> m ByteString

instance MonadRandom IO where
  getRandomBytes = getEntropy
