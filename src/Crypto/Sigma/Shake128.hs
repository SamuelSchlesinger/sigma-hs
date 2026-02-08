{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.Sigma.Shake128
--
-- SHAKE128 duplex sponge implementation backed by Rust FFI.
module Crypto.Sigma.Shake128
  ( Shake128Sponge(..)
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

-- | SHAKE128 duplex sponge wrapping an opaque Rust pointer.
newtype Shake128Sponge = Shake128Sponge (ForeignPtr ShakeSponge)

instance DuplexSponge Shake128Sponge where
  type Unit Shake128Sponge = Word8

  newDuplexSponge iv = unsafePerformIO $ do
    BSU.unsafeUseAsCStringLen iv $ \(ivPtr, ivLen) -> do
      ptr <- sigma_shake128_new (castPtr ivPtr) (fromIntegral ivLen)
      fp <- newForeignPtr sigma_shake128_free_funptr ptr
      return (Shake128Sponge fp)

  absorbDuplexSponge (Shake128Sponge fp) units = unsafePerformIO $ do
    let bs = BS.pack units
    withForeignPtr fp $ \spongePtr ->
      BSU.unsafeUseAsCStringLen bs $ \(dataPtr, dataLen) -> do
        newPtr <- sigma_shake128_clone_and_absorb spongePtr (castPtr dataPtr) (fromIntegral dataLen)
        newFp <- newForeignPtr sigma_shake128_free_funptr newPtr
        return (Shake128Sponge newFp)

  squeezeDuplexSponge (Shake128Sponge fp) n = unsafePerformIO $ do
    withForeignPtr fp $ \spongePtr -> do
      outFp <- mallocForeignPtrBytes n
      withForeignPtr outFp $ \outPtr ->
        sigma_shake128_squeeze_bytes spongePtr (fromIntegral n) outPtr
      let outBs = BSI.BS outFp n
      -- Advance state by absorbing the squeezed output, so that
      -- consecutive squeezes produce different results.
      advancedPtr <- BSU.unsafeUseAsCStringLen outBs $ \(dataPtr, dataLen) ->
        sigma_shake128_clone_and_absorb spongePtr (castPtr dataPtr) (fromIntegral dataLen)
      advancedFp <- newForeignPtr sigma_shake128_free_funptr advancedPtr
      return (BS.unpack outBs, Shake128Sponge advancedFp)
