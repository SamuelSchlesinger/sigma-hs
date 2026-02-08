{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Crypto.Sigma.Protocol (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.Vector as V

import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
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

tests :: TestTree
tests = testGroup "Protocol"
  [ testCase "discrete log: honest prove/verify succeeds" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      (st, commitment) <- proverCommit proof (V.singleton x)
      challenge <- scalarRandom @Ristretto255Scalar
      let response = proverResponse proof st challenge
      assertBool "verification should succeed" (verifier proof commitment challenge response)
  , testCase "DLEQ: honest prove/verify succeeds" $ do
      x <- scalarRandom @Ristretto255Scalar
      bigH <- groupRandom @Ristretto255Point
      let bigX = groupGenerator |*| x
          bigY = bigH |*| x
          lr = buildDleqRelation bigH bigX bigY
          proof = newSchnorrProof lr
      (st, commitment) <- proverCommit proof (V.singleton x)
      challenge <- scalarRandom @Ristretto255Scalar
      let response = proverResponse proof st challenge
      assertBool "verification should succeed" (verifier proof commitment challenge response)
  , testCase "wrong witness fails verification" $ do
      x <- scalarRandom @Ristretto255Scalar
      y <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      -- Use wrong witness y instead of x
      (st, commitment) <- proverCommit proof (V.singleton y)
      challenge <- scalarRandom @Ristretto255Scalar
      let response = proverResponse proof st challenge
      assertBool "verification should fail with wrong witness" (not (verifier proof commitment challenge response))
  , testCase "simulation: simulate + verify succeeds" $ do
      x <- scalarRandom @Ristretto255Scalar
      let bigX = groupGenerator |*| x
          lr = buildDlogRelation bigX
          proof = newSchnorrProof lr
      response <- simulateResponse proof
      challenge <- scalarRandom @Ristretto255Scalar
      let commitment = simulateCommitment proof response challenge
      assertBool "simulated proof should verify" (verifier proof commitment challenge response)
  ]
