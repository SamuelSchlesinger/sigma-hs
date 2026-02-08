{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Crypto.Sigma.Curve25519 (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
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
      , testCase "deserialization rejects wrong length" $ do
          case deserializeScalar @Ristretto255Scalar (BS.replicate 31 0) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject 31-byte scalar"
          case deserializeScalar @Ristretto255Scalar (BS.replicate 33 0) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject 33-byte scalar"
      , testCase "deserialization rejects non-canonical encoding" $ do
          -- All 0xFF bytes is far larger than the group order
          case deserializeScalar @Ristretto255Scalar (BS.replicate 32 0xFF) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject non-canonical scalar (all 0xFF)"
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
      , testCase "deserialization rejects wrong length" $ do
          case deserializeElement @Ristretto255Point (BS.replicate 31 0) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject 31-byte point"
          case deserializeElement @Ristretto255Point (BS.replicate 33 0) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject 33-byte point"
      , testCase "deserialization rejects invalid encoding" $ do
          -- All 0xFF bytes is not a valid Ristretto255 point encoding
          case deserializeElement @Ristretto255Point (BS.replicate 32 0xFF) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject invalid point encoding (all 0xFF)"
          -- 0x01 followed by zeros is also not a valid encoding
          case deserializeElement @Ristretto255Point (BS.singleton 1 <> BS.replicate 31 0) of
            Left _ -> return ()
            Right _ -> assertFailure "should reject invalid point encoding (0x01 prefix)"
      ]
  ]
