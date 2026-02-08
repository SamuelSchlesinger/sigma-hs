{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module: Crypto.Sigma.Curve25519.FFI
--
-- Foreign function interface declarations for the @sigma-ffi@ Rust library
-- (located in @rust\/sigma-ffi\/@). This module provides raw @ccall@ imports
-- for Ristretto255 scalar and group operations, SHAKE128 and Keccak duplex
-- sponge primitives, and cross-compatibility entry points
-- for testing against the sigma-rs Rust reference implementation.
--
-- These bindings are consumed by the higher-level modules
-- "Crypto.Sigma.Curve25519.Ristretto255", "Crypto.Sigma.Shake128",
-- and "Crypto.Sigma.Keccak".
module Crypto.Sigma.Curve25519.FFI where

import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Ptr (Ptr, FunPtr)
import Data.Word (Word8)

-- | Opaque type representing the Rust SHAKE128 sponge state.
data ShakeSponge

-- * Ristretto255 scalar field operations

-- | Write the additive identity (zero) scalar to the output buffer.
foreign import ccall unsafe "sigma_scalar_identity"
  sigma_scalar_identity :: Ptr Word8 -> IO ()

-- | Add two 32-byte scalars, writing the result to the third pointer.
foreign import ccall unsafe "sigma_scalar_add"
  sigma_scalar_add :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

-- | Multiply two 32-byte scalars, writing the result to the third pointer.
foreign import ccall unsafe "sigma_scalar_mul"
  sigma_scalar_mul :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

-- | Negate a 32-byte scalar, writing the result to the second pointer.
foreign import ccall unsafe "sigma_scalar_neg"
  sigma_scalar_neg :: Ptr Word8 -> Ptr Word8 -> IO ()

-- | Compare two 32-byte scalars for equality. Returns 1 if equal, 0 otherwise.
foreign import ccall unsafe "sigma_scalar_eq"
  sigma_scalar_eq :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- | Deserialize a canonical 32-byte scalar. Returns 0 on success, non-zero on
-- failure (non-canonical encoding).
foreign import ccall unsafe "sigma_scalar_deserialize"
  sigma_scalar_deserialize :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- | Reduce 64 uniform bytes to a scalar (for near-uniform sampling).
foreign import ccall unsafe "sigma_scalar_from_wide_bytes"
  sigma_scalar_from_wide_bytes :: Ptr Word8 -> Ptr Word8 -> IO ()

-- * Ristretto255 group element operations

-- | Write the identity (neutral) group element to the output buffer.
foreign import ccall unsafe "sigma_group_identity"
  sigma_group_identity :: Ptr Word8 -> IO ()

-- | Write the standard generator to the output buffer.
foreign import ccall unsafe "sigma_group_generator"
  sigma_group_generator :: Ptr Word8 -> IO ()

-- | Add two 32-byte compressed points, writing the result to the third pointer.
foreign import ccall unsafe "sigma_group_add"
  sigma_group_add :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

-- | Negate a 32-byte compressed point, writing the result to the second pointer.
foreign import ccall unsafe "sigma_group_neg"
  sigma_group_neg :: Ptr Word8 -> Ptr Word8 -> IO ()

-- | Scalar multiplication: point * scalar, writing the result to the third pointer.
foreign import ccall unsafe "sigma_group_scalar_mul"
  sigma_group_scalar_mul :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

-- | Compare two 32-byte compressed points for equality. Returns 1 if equal, 0 otherwise.
foreign import ccall unsafe "sigma_group_eq"
  sigma_group_eq :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- | Deserialize a canonical 32-byte compressed point. Returns 0 on success.
foreign import ccall unsafe "sigma_group_deserialize"
  sigma_group_deserialize :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- | Multi-scalar multiplication: compute @sum_i (points[i] * scalars[i])@.
foreign import ccall unsafe "sigma_group_msm"
  sigma_group_msm :: CSize -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()

-- | Map 64 uniform bytes to a group element (hash-to-group).
foreign import ccall unsafe "sigma_group_from_uniform_bytes"
  sigma_group_from_uniform_bytes :: Ptr Word8 -> Ptr Word8 -> IO ()

-- * SHAKE128 duplex sponge

-- | Create a new SHAKE128 sponge from an initialization vector.
foreign import ccall unsafe "sigma_shake128_new"
  sigma_shake128_new :: Ptr Word8 -> CSize -> IO (Ptr ShakeSponge)

-- | Clone the sponge and absorb data into the clone.
foreign import ccall unsafe "sigma_shake128_clone_and_absorb"
  sigma_shake128_clone_and_absorb :: Ptr ShakeSponge -> Ptr Word8 -> CSize -> IO (Ptr ShakeSponge)

-- | Squeeze bytes from the sponge into the output buffer.
foreign import ccall unsafe "sigma_shake128_squeeze_bytes"
  sigma_shake128_squeeze_bytes :: Ptr ShakeSponge -> CSize -> Ptr Word8 -> IO ()

-- | Clone the sponge state.
foreign import ccall unsafe "sigma_shake128_clone"
  sigma_shake128_clone :: Ptr ShakeSponge -> IO (Ptr ShakeSponge)

-- | Free a sponge state allocated by Rust.
foreign import ccall unsafe "sigma_shake128_free"
  sigma_shake128_free :: Ptr ShakeSponge -> IO ()

-- | Function pointer to 'sigma_shake128_free', for use with @ForeignPtr@.
foreign import ccall unsafe "&sigma_shake128_free"
  sigma_shake128_free_funptr :: FunPtr (Ptr ShakeSponge -> IO ())

-- * Keccak-f[1600] duplex sponge

-- | Opaque type representing the Rust Keccak duplex sponge state.
data KeccakState

-- | Create a new Keccak sponge from a 64-byte initialization vector.
foreign import ccall unsafe "sigma_keccak_new"
  sigma_keccak_new :: Ptr Word8 -> IO (Ptr KeccakState)

-- | Clone the sponge and absorb data into the clone.
foreign import ccall unsafe "sigma_keccak_clone_and_absorb"
  sigma_keccak_clone_and_absorb :: Ptr KeccakState -> Ptr Word8 -> CSize -> IO (Ptr KeccakState)

-- | Clone the sponge, squeeze bytes into the output buffer, and return the
-- advanced sponge state.
foreign import ccall unsafe "sigma_keccak_clone_and_squeeze"
  sigma_keccak_clone_and_squeeze :: Ptr KeccakState -> CSize -> Ptr Word8 -> IO (Ptr KeccakState)

-- | Free a Keccak state allocated by Rust.
foreign import ccall unsafe "sigma_keccak_free"
  sigma_keccak_free :: Ptr KeccakState -> IO ()

-- | Function pointer to 'sigma_keccak_free', for use with @ForeignPtr@.
foreign import ccall unsafe "&sigma_keccak_free"
  sigma_keccak_free_funptr :: FunPtr (Ptr KeccakState -> IO ())

-- * sigma-rs cross-compatibility FFI
--
-- These entry points call into the Rust sigma-rs library to produce and
-- verify proofs, enabling cross-implementation compatibility testing.

-- | Produce a batchable DLOG proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_prove_batchable_dlog"
  sigma_rs_prove_batchable_dlog
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

-- | Verify a batchable DLOG proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_verify_batchable_dlog"
  sigma_rs_verify_batchable_dlog
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- | Produce a compact DLOG proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_prove_compact_dlog"
  sigma_rs_prove_compact_dlog
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

-- | Verify a compact DLOG proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_verify_compact_dlog"
  sigma_rs_verify_compact_dlog
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- | Produce a batchable DLEQ proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_prove_batchable_dleq"
  sigma_rs_prove_batchable_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

-- | Verify a batchable DLEQ proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_verify_batchable_dleq"
  sigma_rs_verify_batchable_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- | Produce a compact DLEQ proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_prove_compact_dleq"
  sigma_rs_prove_compact_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt

-- | Verify a compact DLEQ proof via sigma-rs.
foreign import ccall unsafe "sigma_rs_verify_compact_dleq"
  sigma_rs_verify_compact_dleq
    :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> CSize
    -> Ptr Word8 -> CSize
    -> IO CInt

-- | Compute the DLOG instance label via sigma-rs (for cross-compat testing).
foreign import ccall unsafe "sigma_rs_dlog_instance_label"
  sigma_rs_dlog_instance_label
    :: Ptr Word8 -> Ptr Word8
    -> Ptr Word8 -> Ptr CSize
    -> IO CInt
