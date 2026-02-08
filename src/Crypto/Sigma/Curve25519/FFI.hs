{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module: Crypto.Sigma.Curve25519.FFI
--
-- Foreign function interface declarations for the Rust sigma-ffi library.
module Crypto.Sigma.Curve25519.FFI where

import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Ptr (Ptr, FunPtr)
import Data.Word (Word8)

-- | Opaque type representing the Rust ShakeSponge.
data ShakeSponge

-- Scalar FFI

foreign import ccall unsafe "sigma_scalar_identity"
  sigma_scalar_identity :: Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_scalar_add"
  sigma_scalar_add :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_scalar_mul"
  sigma_scalar_mul :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_scalar_neg"
  sigma_scalar_neg :: Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_scalar_eq"
  sigma_scalar_eq :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "sigma_scalar_deserialize"
  sigma_scalar_deserialize :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "sigma_scalar_from_wide_bytes"
  sigma_scalar_from_wide_bytes :: Ptr Word8 -> Ptr Word8 -> IO ()

-- Group FFI

foreign import ccall unsafe "sigma_group_identity"
  sigma_group_identity :: Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_generator"
  sigma_group_generator :: Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_add"
  sigma_group_add :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_neg"
  sigma_group_neg :: Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_scalar_mul"
  sigma_group_scalar_mul :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_eq"
  sigma_group_eq :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "sigma_group_deserialize"
  sigma_group_deserialize :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "sigma_group_msm"
  sigma_group_msm :: CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_group_from_uniform_bytes"
  sigma_group_from_uniform_bytes :: Ptr Word8 -> Ptr Word8 -> IO ()

-- SHAKE128 FFI

foreign import ccall unsafe "sigma_shake128_new"
  sigma_shake128_new :: Ptr Word8 -> CSize -> IO (Ptr ShakeSponge)

foreign import ccall unsafe "sigma_shake128_clone_and_absorb"
  sigma_shake128_clone_and_absorb :: Ptr ShakeSponge -> Ptr Word8 -> CSize -> IO (Ptr ShakeSponge)

foreign import ccall unsafe "sigma_shake128_squeeze_bytes"
  sigma_shake128_squeeze_bytes :: Ptr ShakeSponge -> CSize -> Ptr Word8 -> IO ()

foreign import ccall unsafe "sigma_shake128_clone"
  sigma_shake128_clone :: Ptr ShakeSponge -> IO (Ptr ShakeSponge)

foreign import ccall unsafe "sigma_shake128_free"
  sigma_shake128_free :: Ptr ShakeSponge -> IO ()

foreign import ccall unsafe "&sigma_shake128_free"
  sigma_shake128_free_funptr :: FunPtr (Ptr ShakeSponge -> IO ())

-- Keccak FFI

-- | Opaque type representing the Rust KeccakState.
data KeccakState

foreign import ccall unsafe "sigma_keccak_new"
  sigma_keccak_new :: Ptr Word8 -> IO (Ptr KeccakState)

foreign import ccall unsafe "sigma_keccak_clone_and_absorb"
  sigma_keccak_clone_and_absorb :: Ptr KeccakState -> Ptr Word8 -> CSize -> IO (Ptr KeccakState)

foreign import ccall unsafe "sigma_keccak_clone_and_squeeze"
  sigma_keccak_clone_and_squeeze :: Ptr KeccakState -> CSize -> Ptr Word8 -> IO (Ptr KeccakState)

foreign import ccall unsafe "sigma_keccak_free"
  sigma_keccak_free :: Ptr KeccakState -> IO ()

foreign import ccall unsafe "&sigma_keccak_free"
  sigma_keccak_free_funptr :: FunPtr (Ptr KeccakState -> IO ())

-- sigma-rs cross-compatibility FFI

-- DLOG batchable
foreign import ccall unsafe "sigma_rs_prove_batchable_dlog"
  sigma_rs_prove_batchable_dlog
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "sigma_rs_verify_batchable_dlog"
  sigma_rs_verify_batchable_dlog
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- DLOG compact
foreign import ccall unsafe "sigma_rs_prove_compact_dlog"
  sigma_rs_prove_compact_dlog
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "sigma_rs_verify_compact_dlog"
  sigma_rs_verify_compact_dlog
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- DLEQ batchable
foreign import ccall unsafe "sigma_rs_prove_batchable_dleq"
  sigma_rs_prove_batchable_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "sigma_rs_verify_batchable_dleq"
  sigma_rs_verify_batchable_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- DLEQ compact
foreign import ccall unsafe "sigma_rs_prove_compact_dleq"
  sigma_rs_prove_compact_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

foreign import ccall unsafe "sigma_rs_verify_compact_dleq"
  sigma_rs_verify_compact_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- Instance label
foreign import ccall unsafe "sigma_rs_dlog_instance_label"
  sigma_rs_dlog_instance_label
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

-- Random FFI

foreign import ccall unsafe "sigma_random_bytes"
  sigma_random_bytes :: Ptr Word8 -> CSize -> IO ()
