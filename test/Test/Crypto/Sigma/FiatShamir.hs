{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.Sigma.FiatShamir (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import qualified Data.Vector as V

import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
import Crypto.Sigma.FiatShamir
import Crypto.Sigma.Shake128 (Shake128Sponge)
import Crypto.Sigma.Curve25519.Ristretto255

-- | Build a discrete log proof: X = x * G
buildDlogRelation :: Ristretto255Point -> LinearRelation Ristretto255Point
buildDlogRelation bigX = buildLinearRelation_ $ do
  sIdx <- allocateScalars 1
  eIdx <- allocateElements 2
  setElements [(eIdx V.! 0, groupGenerator), (eIdx V.! 1, bigX)]
  appendEquation (eIdx V.! 1) [(sIdx V.! 0, eIdx V.! 0)]

-- | Build a DLEQ proof: X = x * G, Y = x * H
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

sponge :: Shake128Sponge
sponge = makeIV "sigma-protocol-v1" "test-session"

wrongSponge :: Shake128Sponge
wrongSponge = makeIV "sigma-protocol-v1" "wrong-session"

-- | Assert that a verification result is a rejection.
assertRejects :: String -> Either a Bool -> Assertion
assertRejects _ (Left _) = return ()
assertRejects _ (Right False) = return ()
assertRejects msg (Right True) = assertFailure msg

tests :: TestTree
tests = testGroup "FiatShamir"
  [ testCase "compact: dlog prove/verify round-trip" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      case verify @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
        Left err -> assertFailure ("deserialization failed: " ++ show err)
        Right ok -> assertBool "compact proof should verify" ok
  , testCase "compact: DLEQ prove/verify round-trip" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      case verify @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
        Left err -> assertFailure ("deserialization failed: " ++ show err)
        Right ok -> assertBool "compact DLEQ proof should verify" ok
  , testCase "batchable: prove/verify round-trip" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      case verifyBatchable @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
        Left err -> assertFailure ("deserialization failed: " ++ show err)
        Right ok -> assertBool "batchable proof should verify" ok
  , testCase "tampered compact proof fails verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      -- Tamper in the response portion (after the 32-byte challenge)
      let idx = 32 + 5
          tampered = BS.take idx proofBytes <> BS.singleton (BS.index proofBytes idx + 1) <> BS.drop (idx + 1) proofBytes
      assertRejects "tampered compact proof should not verify" $
        verify @Ristretto255Point @Shake128Sponge sponge proof tampered
  , testCase "tampered batchable proof fails verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      -- Tamper in the response portion (after the 32-byte commitment)
      let idx = 32 + 5
          tampered = BS.take idx proofBytes <> BS.singleton (BS.index proofBytes idx + 1) <> BS.drop (idx + 1) proofBytes
      assertRejects "tampered batchable proof should not verify" $
        verifyBatchable @Ristretto255Point @Shake128Sponge sponge proof tampered

  -- ── Negative tests: wrong session ID ─────────────────────────────────

  , testCase "REJECT: wrong session fails compact verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      assertRejects "wrong session should fail compact verify" $
        verify @Ristretto255Point @Shake128Sponge wrongSponge proof proofBytes
  , testCase "REJECT: wrong session fails batchable verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      assertRejects "wrong session should fail batchable verify" $
        verifyBatchable @Ristretto255Point @Shake128Sponge wrongSponge proof proofBytes

  -- ── Negative tests: wrong public key ─────────────────────────────────

  , testCase "REJECT: wrong key fails compact verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      y <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          bigY = groupGenerator |*| y
          proofX = newSchnorrProof (buildDlogRelation bigX)
          proofY = newSchnorrProof (buildDlogRelation bigY)
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proofX (V.singleton x)
      assertRejects "wrong key should fail compact verify" $
        verify @Ristretto255Point @Shake128Sponge sponge proofY proofBytes
  , testCase "REJECT: wrong key fails batchable verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      y <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          bigY = groupGenerator |*| y
          proofX = newSchnorrProof (buildDlogRelation bigX)
          proofY = newSchnorrProof (buildDlogRelation bigY)
      proofBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proofX (V.singleton x)
      assertRejects "wrong key should fail batchable verify" $
        verifyBatchable @Ristretto255Point @Shake128Sponge sponge proofY proofBytes

  -- ── Negative tests: proof format mismatch ────────────────────────────

  , testCase "REJECT: batchable proof fails compact verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      assertRejects "batchable proof should fail compact verify" $
        verify @Ristretto255Point @Shake128Sponge sponge proof proofBytes
  , testCase "REJECT: compact proof fails batchable verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      assertRejects "compact proof should fail batchable verify" $
        verifyBatchable @Ristretto255Point @Shake128Sponge sponge proof proofBytes
  ]
