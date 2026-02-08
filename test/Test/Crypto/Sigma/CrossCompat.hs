{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.Sigma.CrossCompat (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.Types (CSize(..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr)
import qualified Data.Vector as V

import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
import Crypto.Sigma.FiatShamir
import Crypto.Sigma.Keccak (KeccakSponge)
import Crypto.Sigma.Curve25519.FFI
import Crypto.Sigma.Curve25519.Ristretto255

-- | Protocol ID matching sigma-rs: "ietf sigma proof linear relation" + 32 zero bytes
protocolId :: ByteString
protocolId = "ietf sigma proof linear relation" <> BS.replicate 32 0

-- | Build a discrete log relation: X = x * G
buildDlogRelation :: Ristretto255Point -> LinearRelation Ristretto255Point
buildDlogRelation bigX = buildLinearRelation_ $ do
  sIdx <- allocateScalars 1
  eIdx <- allocateElements 2
  setElements [(eIdx V.! 0, groupGenerator), (eIdx V.! 1, bigX)]
  appendEquation (eIdx V.! 1) [(sIdx V.! 0, eIdx V.! 0)]

-- | Build a DLEQ relation: X = x * G, Y = x * H
buildDleqRelation :: Ristretto255Point -> Ristretto255Point -> Ristretto255Point -> LinearRelation Ristretto255Point
buildDleqRelation bigH bigX bigY = buildLinearRelation_ $ do
  sIdx <- allocateScalars 1
  eIdx <- allocateElements 4
  setElements [ (eIdx V.! 0, groupGenerator)
              , (eIdx V.! 1, bigH)
              , (eIdx V.! 2, bigX)
              , (eIdx V.! 3, bigY)
              ]
  appendEquation (eIdx V.! 2) [(sIdx V.! 0, eIdx V.! 0)]
  appendEquation (eIdx V.! 3) [(sIdx V.! 0, eIdx V.! 1)]

-- Helpers for ByteString <-> C pointer conversions

withBS :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withBS bs f = BSU.unsafeUseAsCString bs (f . castPtr)

-- | Call sigma-rs to prove dlog (batchable)
rsProveBatchableDlog :: Ristretto255Point -> Ristretto255Point
                     -> Ristretto255Scalar -> ByteString -> IO (Either Int ByteString)
rsProveBatchableDlog (Ristretto255Point gen) (Ristretto255Point pk) (Ristretto255Scalar w) sid = do
  withBS gen $ \pGen ->
    withBS pk $ \pPk ->
      withBS w $ \pW ->
        BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
          allocaBytes 1024 $ \pOut ->
            allocaBytes 8 $ \pLen -> do
              r <- sigma_rs_prove_batchable_dlog pGen pPk pW (castPtr sidPtr)
                     (fromIntegral sidLen) pOut pLen
              if r == 0
                then do
                  len <- peek pLen
                  proofBS <- BS.packCStringLen (castPtr pOut, fromIntegral len)
                  return (Right proofBS)
                else return (Left (fromIntegral r))
  where
    peek :: Ptr CSize -> IO CSize
    peek p = do
      let pWord = castPtr p :: Ptr Word8
      bytes <- BS.packCStringLen (castPtr pWord, 8)
      let vals = BS.unpack bytes
      return $ fromIntegral $ foldl (\acc (b, i) -> acc + fromIntegral b * (256 ^ i)) (0 :: Integer) (zip vals [0..7 :: Int])

-- | Call sigma-rs to verify dlog (batchable)
rsVerifyBatchableDlog :: Ristretto255Point -> Ristretto255Point
                      -> ByteString -> ByteString -> IO Int
rsVerifyBatchableDlog (Ristretto255Point gen) (Ristretto255Point pk) sid proof = do
  withBS gen $ \pGen ->
    withBS pk $ \pPk ->
      BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
        BSU.unsafeUseAsCStringLen proof $ \(proofPtr, proofLen) -> do
          r <- sigma_rs_verify_batchable_dlog pGen pPk (castPtr sidPtr) (fromIntegral sidLen)
                 (castPtr proofPtr) (fromIntegral proofLen)
          return (fromIntegral r)

-- | Call sigma-rs to prove dlog (compact)
rsProveCompactDlog :: Ristretto255Point -> Ristretto255Point
                   -> Ristretto255Scalar -> ByteString -> IO (Either Int ByteString)
rsProveCompactDlog (Ristretto255Point gen) (Ristretto255Point pk) (Ristretto255Scalar w) sid = do
  withBS gen $ \pGen ->
    withBS pk $ \pPk ->
      withBS w $ \pW ->
        BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
          allocaBytes 1024 $ \pOut ->
            allocaBytes 8 $ \pLen -> do
              r <- sigma_rs_prove_compact_dlog pGen pPk pW (castPtr sidPtr)
                     (fromIntegral sidLen) pOut pLen
              if r == 0
                then do
                  len <- peekCSize pLen
                  proofBS <- BS.packCStringLen (castPtr pOut, fromIntegral len)
                  return (Right proofBS)
                else return (Left (fromIntegral r))

-- | Call sigma-rs to verify dlog (compact)
rsVerifyCompactDlog :: Ristretto255Point -> Ristretto255Point
                    -> ByteString -> ByteString -> IO Int
rsVerifyCompactDlog (Ristretto255Point gen) (Ristretto255Point pk) sid proof = do
  withBS gen $ \pGen ->
    withBS pk $ \pPk ->
      BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
        BSU.unsafeUseAsCStringLen proof $ \(proofPtr, proofLen) -> do
          r <- sigma_rs_verify_compact_dlog pGen pPk (castPtr sidPtr) (fromIntegral sidLen)
                 (castPtr proofPtr) (fromIntegral proofLen)
          return (fromIntegral r)

-- | Call sigma-rs to prove DLEQ (batchable)
rsProveBatchableDleq :: Ristretto255Point -> Ristretto255Point
                     -> Ristretto255Point -> Ristretto255Point
                     -> Ristretto255Scalar -> ByteString -> IO (Either Int ByteString)
rsProveBatchableDleq (Ristretto255Point g1) (Ristretto255Point p1)
                     (Ristretto255Point g2) (Ristretto255Point p2)
                     (Ristretto255Scalar w) sid = do
  withBS g1 $ \pG1 ->
    withBS p1 $ \pP1 ->
      withBS g2 $ \pG2 ->
        withBS p2 $ \pP2 ->
          withBS w $ \pW ->
            BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
              allocaBytes 1024 $ \pOut ->
                allocaBytes 8 $ \pLen -> do
                  r <- sigma_rs_prove_batchable_dleq pG1 pP1 pG2 pP2 pW (castPtr sidPtr)
                         (fromIntegral sidLen) pOut pLen
                  if r == 0
                    then do
                      len <- peekCSize pLen
                      proofBS <- BS.packCStringLen (castPtr pOut, fromIntegral len)
                      return (Right proofBS)
                    else return (Left (fromIntegral r))

-- | Call sigma-rs to verify DLEQ (batchable)
rsVerifyBatchableDleq :: Ristretto255Point -> Ristretto255Point
                      -> Ristretto255Point -> Ristretto255Point
                      -> ByteString -> ByteString -> IO Int
rsVerifyBatchableDleq (Ristretto255Point g1) (Ristretto255Point p1)
                      (Ristretto255Point g2) (Ristretto255Point p2) sid proof = do
  withBS g1 $ \pG1 ->
    withBS p1 $ \pP1 ->
      withBS g2 $ \pG2 ->
        withBS p2 $ \pP2 ->
          BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
            BSU.unsafeUseAsCStringLen proof $ \(proofPtr, proofLen) -> do
              r <- sigma_rs_verify_batchable_dleq pG1 pP1 pG2 pP2 (castPtr sidPtr) (fromIntegral sidLen)
                     (castPtr proofPtr) (fromIntegral proofLen)
              return (fromIntegral r)

-- | Call sigma-rs to prove DLEQ (compact)
rsProveCompactDleq :: Ristretto255Point -> Ristretto255Point
                   -> Ristretto255Point -> Ristretto255Point
                   -> Ristretto255Scalar -> ByteString -> IO (Either Int ByteString)
rsProveCompactDleq (Ristretto255Point g1) (Ristretto255Point p1)
                   (Ristretto255Point g2) (Ristretto255Point p2)
                   (Ristretto255Scalar w) sid = do
  withBS g1 $ \pG1 ->
    withBS p1 $ \pP1 ->
      withBS g2 $ \pG2 ->
        withBS p2 $ \pP2 ->
          withBS w $ \pW ->
            BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
              allocaBytes 1024 $ \pOut ->
                allocaBytes 8 $ \pLen -> do
                  r <- sigma_rs_prove_compact_dleq pG1 pP1 pG2 pP2 pW (castPtr sidPtr)
                         (fromIntegral sidLen) pOut pLen
                  if r == 0
                    then do
                      len <- peekCSize pLen
                      proofBS <- BS.packCStringLen (castPtr pOut, fromIntegral len)
                      return (Right proofBS)
                    else return (Left (fromIntegral r))

-- | Call sigma-rs to verify DLEQ (compact)
rsVerifyCompactDleq :: Ristretto255Point -> Ristretto255Point
                    -> Ristretto255Point -> Ristretto255Point
                    -> ByteString -> ByteString -> IO Int
rsVerifyCompactDleq (Ristretto255Point g1) (Ristretto255Point p1)
                    (Ristretto255Point g2) (Ristretto255Point p2) sid proof = do
  withBS g1 $ \pG1 ->
    withBS p1 $ \pP1 ->
      withBS g2 $ \pG2 ->
        withBS p2 $ \pP2 ->
          BSU.unsafeUseAsCStringLen sid $ \(sidPtr, sidLen) ->
            BSU.unsafeUseAsCStringLen proof $ \(proofPtr, proofLen) -> do
              r <- sigma_rs_verify_compact_dleq pG1 pP1 pG2 pP2 (castPtr sidPtr) (fromIntegral sidLen)
                     (castPtr proofPtr) (fromIntegral proofLen)
              return (fromIntegral r)

-- | Get dlog instance label from sigma-rs
rsGetDlogLabel :: Ristretto255Point -> Ristretto255Point -> IO (Either Int ByteString)
rsGetDlogLabel (Ristretto255Point gen) (Ristretto255Point pk) = do
  withBS gen $ \pGen ->
    withBS pk $ \pPk ->
      allocaBytes 1024 $ \pOut ->
        allocaBytes 8 $ \pLen -> do
          r <- sigma_rs_dlog_instance_label pGen pPk pOut pLen
          if r == 0
            then do
              len <- peekCSize pLen
              labelBS <- BS.packCStringLen (castPtr pOut, fromIntegral len)
              return (Right labelBS)
            else return (Left (fromIntegral r))

-- | Peek a CSize from a pointer (platform-dependent size)
peekCSize :: Ptr CSize -> IO CSize
peekCSize p = do
  let pWord = castPtr p :: Ptr Word8
  bytes <- BS.packCStringLen (castPtr pWord, 8)
  let vals = BS.unpack bytes
  return $ fromIntegral $ foldl (\acc (b, i) -> acc + fromIntegral b * (256 ^ i)) (0 :: Integer) (zip vals [0..7 :: Int])

-- | Session ID used for all cross-compat tests
sessionId :: ByteString
sessionId = "cross-compat-test-session"

-- | Create the Keccak sponge for sigma-hs
keccakSponge :: KeccakSponge
keccakSponge = makeIV protocolId sessionId

tests :: TestTree
tests = testGroup "CrossCompat"
  [ testCase "label-match: dlog instance labels agree" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          hsLabel = getInstanceLabel lr
      rsResult <- rsGetDlogLabel groupGenerator bigX
      case rsResult of
        Left err -> assertFailure ("sigma-rs label failed: " ++ show err)
        Right rsLabel -> hsLabel @?= rsLabel

  , testCase "hs-prove -> rs-verify: dlog batchable" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @KeccakSponge keccakSponge proof (V.singleton x)
      result <- rsVerifyBatchableDlog groupGenerator bigX sessionId proofBytes
      assertEqual "sigma-rs should accept sigma-hs proof" 0 result

  , testCase "rs-prove -> hs-verify: dlog batchable" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      rsResult <- rsProveBatchableDlog groupGenerator bigX x sessionId
      case rsResult of
        Left err -> assertFailure ("sigma-rs prove failed: " ++ show err)
        Right proofBytes ->
          case verifyBatchable @Ristretto255Point @KeccakSponge keccakSponge proof proofBytes of
            Left err -> assertFailure ("deserialization failed: " ++ show err)
            Right ok -> assertBool "sigma-hs should accept sigma-rs proof" ok

  , testCase "hs-prove -> rs-verify: dlog compact" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @KeccakSponge keccakSponge proof (V.singleton x)
      result <- rsVerifyCompactDlog groupGenerator bigX sessionId proofBytes
      assertEqual "sigma-rs should accept sigma-hs compact proof" 0 result

  , testCase "rs-prove -> hs-verify: dlog compact" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      rsResult <- rsProveCompactDlog groupGenerator bigX x sessionId
      case rsResult of
        Left err -> assertFailure ("sigma-rs compact prove failed: " ++ show err)
        Right proofBytes ->
          case verify @Ristretto255Point @KeccakSponge keccakSponge proof proofBytes of
            Left err -> assertFailure ("deserialization failed: " ++ show err)
            Right ok -> assertBool "sigma-hs should accept sigma-rs compact proof" ok

  , testCase "hs-prove -> rs-verify: DLEQ batchable" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @KeccakSponge keccakSponge proof (V.singleton x)
      result <- rsVerifyBatchableDleq groupGenerator bigX bigH bigY sessionId proofBytes
      assertEqual "sigma-rs should accept sigma-hs DLEQ proof" 0 result

  , testCase "rs-prove -> hs-verify: DLEQ batchable" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      rsResult <- rsProveBatchableDleq groupGenerator bigX bigH bigY x sessionId
      case rsResult of
        Left err -> assertFailure ("sigma-rs DLEQ prove failed: " ++ show err)
        Right proofBytes ->
          case verifyBatchable @Ristretto255Point @KeccakSponge keccakSponge proof proofBytes of
            Left err -> assertFailure ("deserialization failed: " ++ show err)
            Right ok -> assertBool "sigma-hs should accept sigma-rs DLEQ proof" ok

  , testCase "hs-prove -> rs-verify: DLEQ compact" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @KeccakSponge keccakSponge proof (V.singleton x)
      result <- rsVerifyCompactDleq groupGenerator bigX bigH bigY sessionId proofBytes
      assertEqual "sigma-rs should accept sigma-hs compact DLEQ proof" 0 result

  , testCase "rs-prove -> hs-verify: DLEQ compact" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      rsResult <- rsProveCompactDleq groupGenerator bigX bigH bigY x sessionId
      case rsResult of
        Left err -> assertFailure ("sigma-rs compact DLEQ prove failed: " ++ show err)
        Right proofBytes ->
          case verify @Ristretto255Point @KeccakSponge keccakSponge proof proofBytes of
            Left err -> assertFailure ("deserialization failed: " ++ show err)
            Right ok -> assertBool "sigma-hs should accept sigma-rs compact DLEQ proof" ok

  , testCase "label is order-independent: DLEQ two allocation orders" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x

          -- Order A: all elements in one batch [G, H, X, Y]
          lrA = buildDleqRelation bigH bigX bigY

          -- Order B: canonical order [G, X, H, Y]
          lrB = buildLinearRelation_ $ do
            sIdx <- allocateScalars 1
            gIdx <- allocateElements 1  -- 0: G
            xIdx <- allocateElements 1  -- 1: X
            hIdx <- allocateElements 1  -- 2: H
            yIdx <- allocateElements 1  -- 3: Y
            setElements [ (gIdx V.! 0, groupGenerator)
                        , (xIdx V.! 0, bigX)
                        , (hIdx V.! 0, bigH)
                        , (yIdx V.! 0, bigY)
                        ]
            appendEquation (xIdx V.! 0) [(sIdx V.! 0, gIdx V.! 0)]
            appendEquation (yIdx V.! 0) [(sIdx V.! 0, hIdx V.! 0)]

      assertEqual "labels should be identical regardless of allocation order"
        (getInstanceLabel lrA) (getInstanceLabel lrB)
  ]
