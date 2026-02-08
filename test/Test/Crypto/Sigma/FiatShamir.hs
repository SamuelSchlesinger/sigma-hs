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
  , testCase "tampered proof fails verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof (V.singleton x)
      -- Flip a byte in the proof
      let tampered = BS.take 10 proofBytes <> BS.singleton (BS.index proofBytes 10 + 1) <> BS.drop 11 proofBytes
      case verify @Ristretto255Point @Shake128Sponge sponge proof tampered of
        Left _err -> return () -- Deserialization failure is also a valid rejection
        Right ok -> assertBool "tampered proof should not verify" (not ok)
  ]
