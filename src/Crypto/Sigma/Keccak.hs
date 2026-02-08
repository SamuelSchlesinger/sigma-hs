{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.Sigma.Keccak
--
-- Keccak duplex sponge implementation backed by Rust FFI, matching
-- sigma-rs's KeccakDuplexSponge (Keccak-f[1600], RATE=136, CAPACITY=64).
module Crypto.Sigma.Keccak
  ( KeccakSponge(..)
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Data.Word (Word8)
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr, newForeignPtr, mallocForeignPtrBytes)
import Foreign.Ptr (castPtr)
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Sigma.DuplexSponge
import Crypto.Sigma.Curve25519.FFI

-- | Keccak duplex sponge wrapping an opaque Rust pointer.
newtype KeccakSponge = KeccakSponge (ForeignPtr KeccakState)

instance DuplexSponge KeccakSponge where
  type Unit KeccakSponge = Word8

  newDuplexSponge iv = unsafePerformIO $ do
    -- Pad or truncate IV to exactly 64 bytes (capacity size)
    let paddedIV = BS.take 64 (iv <> BS.replicate 64 0)
    BSU.unsafeUseAsCString paddedIV $ \ivPtr -> do
      ptr <- sigma_keccak_new (castPtr ivPtr)
      fp <- newForeignPtr sigma_keccak_free_funptr ptr
      return (KeccakSponge fp)

  absorbDuplexSponge (KeccakSponge fp) units = unsafePerformIO $ do
    let bs = BS.pack units
    withForeignPtr fp $ \spongePtr ->
      BSU.unsafeUseAsCStringLen bs $ \(dataPtr, dataLen) -> do
        newPtr <- sigma_keccak_clone_and_absorb spongePtr (castPtr dataPtr) (fromIntegral dataLen)
        newFp <- newForeignPtr sigma_keccak_free_funptr newPtr
        return (KeccakSponge newFp)

  squeezeDuplexSponge (KeccakSponge fp) n = unsafePerformIO $ do
    withForeignPtr fp $ \spongePtr -> do
      outFp <- mallocForeignPtrBytes n
      -- clone_and_squeeze returns the advanced sponge state
      advancedPtr <- withForeignPtr outFp $ \outPtr ->
        sigma_keccak_clone_and_squeeze spongePtr (fromIntegral n) outPtr
      let outBs = BSI.BS outFp n
      advancedFp <- newForeignPtr sigma_keccak_free_funptr advancedPtr
      return (BS.unpack outBs, KeccakSponge advancedFp)
