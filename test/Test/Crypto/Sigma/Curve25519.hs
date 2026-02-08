{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Crypto.Sigma.Curve25519 (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.Vector as V

import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.Curve25519.Ristretto255

tests :: TestTree
tests = testGroup "Curve25519"
  [ testGroup "Scalar"
      [ testCase "additive identity" $ do
          s <- scalarRandom @Ristretto255Scalar
          s .+. scalarIdentity @?= s
          scalarIdentity .+. s @?= s
      , testCase "additive inverse" $ do
          s <- scalarRandom @Ristretto255Scalar
          s .+. scalarNeg s @?= scalarIdentity
      , testCase "commutativity" $ do
          a <- scalarRandom @Ristretto255Scalar
          b <- scalarRandom @Ristretto255Scalar
          a .+. b @?= b .+. a
      , testCase "associativity" $ do
          a <- scalarRandom @Ristretto255Scalar
          b <- scalarRandom @Ristretto255Scalar
          c <- scalarRandom @Ristretto255Scalar
          (a .+. b) .+. c @?= a .+. (b .+. c)
      , testCase "subtraction consistency" $ do
          a <- scalarRandom @Ristretto255Scalar
          b <- scalarRandom @Ristretto255Scalar
          a .-. b @?= a .+. scalarNeg b
      , testCase "serialization round-trip" $ do
          s <- scalarRandom @Ristretto255Scalar
          deserializeScalar (serializeScalar s) @?= Right s
      ]
  , testGroup "Group"
      [ testCase "generator /= identity" $
          (groupGenerator @Ristretto255Point) /= groupIdentity @? "generator should not equal identity"
      , testCase "scalar mul distributes over addition" $ do
          s1 <- scalarRandom @Ristretto255Scalar
          s2 <- scalarRandom @Ristretto255Scalar
          let g = groupGenerator @Ristretto255Point
          g |*| (s1 .+. s2) @?= (g |*| s1) |+| (g |*| s2)
      , testCase "MSM correctness" $ do
          s1 <- scalarRandom @Ristretto255Scalar
          s2 <- scalarRandom @Ristretto255Scalar
          g1 <- groupRandom @Ristretto255Point
          g2 <- groupRandom @Ristretto255Point
          msm (V.fromList [s1, s2]) (V.fromList [g1, g2]) @?= (g1 |*| s1) |+| (g2 |*| s2)
      , testCase "serialization round-trip" $ do
          p <- groupRandom @Ristretto255Point
          deserializeElement (serializeElement p) @?= Right p
      , testCase "identity properties" $ do
          p <- groupRandom @Ristretto255Point
          p |+| groupIdentity @?= p
          groupIdentity |+| p @?= p
      ]
  ]
