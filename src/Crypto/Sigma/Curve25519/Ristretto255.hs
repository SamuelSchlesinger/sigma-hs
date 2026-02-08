{-# LANGUAGE TypeFamilies #-}

-- |
-- Module: Crypto.Sigma.Curve25519.Ristretto255
--
-- Ristretto255 group and scalar field implementations backed by
-- curve25519-dalek via Rust FFI.
module Crypto.Sigma.Curve25519.Ristretto255
  ( Ristretto255Scalar(..)
  , Ristretto255Point(..)
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.ForeignPtr (withForeignPtr, mallocForeignPtrBytes)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.Vector as V

import Crypto.Sigma.Error (DeserializeError(..))
import Crypto.Sigma.Random (MonadRandom(..))
import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.Curve25519.FFI

-- | A scalar in the Ristretto255 scalar field, stored as 32 bytes
-- in little-endian canonical form.
newtype Ristretto255Scalar = Ristretto255Scalar ByteString
  deriving (Show)

-- | A compressed Ristretto255 point, stored as 32 bytes.
newtype Ristretto255Point = Ristretto255Point ByteString
  deriving (Show)

instance Eq Ristretto255Scalar where
  Ristretto255Scalar a == Ristretto255Scalar b = unsafePerformIO $
    withBS a $ \pa ->
    withBS b $ \pb -> do
      r <- sigma_scalar_eq pa pb
      return (r == 1)

instance Eq Ristretto255Point where
  Ristretto255Point a == Ristretto255Point b = unsafePerformIO $
    withBS a $ \pa ->
    withBS b $ \pb -> do
      r <- sigma_group_eq pa pb
      return (r == 1)

instance Scalar Ristretto255Scalar where
  scalarIdentity = unsafePerformIO $ do
    out <- createBS 32 sigma_scalar_identity
    return (Ristretto255Scalar out)

  scalarAdd (Ristretto255Scalar a) (Ristretto255Scalar b) = unsafePerformIO $
    withBS a $ \pa ->
    withBS b $ \pb -> do
      out <- createBS 32 (\po -> sigma_scalar_add pa pb po)
      return (Ristretto255Scalar out)

  scalarMul (Ristretto255Scalar a) (Ristretto255Scalar b) = unsafePerformIO $
    withBS a $ \pa ->
    withBS b $ \pb -> do
      out <- createBS 32 (\po -> sigma_scalar_mul pa pb po)
      return (Ristretto255Scalar out)

  scalarNeg (Ristretto255Scalar a) = unsafePerformIO $
    withBS a $ \pa -> do
      out <- createBS 32 (\po -> sigma_scalar_neg pa po)
      return (Ristretto255Scalar out)

  scalarRandom = do
    wide <- getRandomBytes 64
    return $ unsafePerformIO $
      withBS wide $ \pw -> do
        out <- createBS 32 (\po -> sigma_scalar_from_wide_bytes pw po)
        return (Ristretto255Scalar out)

  scalarSize = 32

  serializeScalar (Ristretto255Scalar bs) = bs

  deserializeScalar bs
    | BS.length bs /= 32 = Left (DeserializeError "scalar must be 32 bytes")
    | otherwise = unsafePerformIO $
        withBS bs $ \pin -> do
          allocaBytes 32 $ \pout -> do
            r <- sigma_scalar_deserialize pin pout
            if r == 0
              then do
                out <- copyToBS pout 32
                return (Right (Ristretto255Scalar out))
              else return (Left (DeserializeError "non-canonical scalar encoding"))

  scalarFromUniformBytes bs =
    let -- We need 48 bytes (scalarSize + 16), pad to 64 for the FFI
        -- Input is big-endian, dalek expects little-endian
        padded = BS.reverse bs <> BS.replicate (64 - BS.length bs) 0
        wide = BS.take 64 padded
    in unsafePerformIO $
      withBS wide $ \pw -> do
        out <- createBS 32 (\po -> sigma_scalar_from_wide_bytes pw po)
        return (Ristretto255Scalar out)

instance Group Ristretto255Point where
  type GroupScalar Ristretto255Point = Ristretto255Scalar

  groupIdentity = unsafePerformIO $ do
    out <- createBS 32 sigma_group_identity
    return (Ristretto255Point out)

  groupGenerator = unsafePerformIO $ do
    out <- createBS 32 sigma_group_generator
    return (Ristretto255Point out)

  groupOrder = 2^(252 :: Integer) + 27742317777372353535851937790883648493

  groupRandom = do
    wide <- getRandomBytes 64
    return $ unsafePerformIO $
      withBS wide $ \pw -> do
        out <- createBS 32 (\po -> sigma_group_from_uniform_bytes pw po)
        return (Ristretto255Point out)

  groupAdd (Ristretto255Point a) (Ristretto255Point b) = unsafePerformIO $
    withBS a $ \pa ->
    withBS b $ \pb -> do
      out <- createBS 32 (\po -> sigma_group_add pa pb po)
      return (Ristretto255Point out)

  groupNeg (Ristretto255Point a) = unsafePerformIO $
    withBS a $ \pa -> do
      out <- createBS 32 (\po -> sigma_group_neg pa po)
      return (Ristretto255Point out)

  groupScalarMul (Ristretto255Point p) (Ristretto255Scalar s) = unsafePerformIO $
    withBS p $ \pp ->
    withBS s $ \ps -> do
      out <- createBS 32 (\po -> sigma_group_scalar_mul pp ps po)
      return (Ristretto255Point out)

  msm scalars points = unsafePerformIO $ do
    let n = V.length scalars
        scalarBytes = BS.concat $ V.toList $ V.map (\(Ristretto255Scalar s) -> s) scalars
        pointBytes = BS.concat $ V.toList $ V.map (\(Ristretto255Point p) -> p) points
    withBS scalarBytes $ \ps ->
      withBS pointBytes $ \pp -> do
        out <- createBS 32 (\po -> sigma_group_msm (fromIntegral n) ps pp po)
        return (Ristretto255Point out)

  elementSize = 32

  serializeElement (Ristretto255Point bs) = bs

  deserializeElement bs
    | BS.length bs /= 32 = Left (DeserializeError "element must be 32 bytes")
    | otherwise = unsafePerformIO $
        withBS bs $ \pin -> do
          allocaBytes 32 $ \pout -> do
            r <- sigma_group_deserialize pin pout
            if r == 0
              then do
                out <- copyToBS pout 32
                return (Right (Ristretto255Point out))
              else return (Left (DeserializeError "invalid Ristretto point encoding"))

-- Helpers

withBS :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withBS bs f = BSU.unsafeUseAsCString bs (f . castPtr)

createBS :: Int -> (Ptr Word8 -> IO ()) -> IO ByteString
createBS n f = do
  fp <- mallocForeignPtrBytes n
  withForeignPtr fp $ \p -> f p
  return (BSI.BS fp n)

copyToBS :: Ptr Word8 -> Int -> IO ByteString
copyToBS p n = BS.packCStringLen (castPtr p, n)
