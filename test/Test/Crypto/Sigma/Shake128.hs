{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.Sigma.Shake128 (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import Data.Word (Word8)

import Crypto.Sigma.DuplexSponge
import Crypto.Sigma.Shake128 (Shake128Sponge)

tests :: TestTree
tests = testGroup "Shake128"
  [ testCase "determinism" $ do
      let s1 = newDuplexSponge "test-iv" :: Shake128Sponge
          s2 = newDuplexSponge "test-iv" :: Shake128Sponge
          (out1, _) = squeezeDuplexSponge s1 32
          (out2, _) = squeezeDuplexSponge s2 32
      out1 @?= out2
  , testCase "different IVs produce different output" $ do
      let s1 = newDuplexSponge "iv-one" :: Shake128Sponge
          s2 = newDuplexSponge "iv-two" :: Shake128Sponge
          (out1, _) = squeezeDuplexSponge s1 32
          (out2, _) = squeezeDuplexSponge s2 32
      assertBool "different IVs should produce different output" (out1 /= out2)
  , testCase "absorb changes output" $ do
      let s = newDuplexSponge "test-iv" :: Shake128Sponge
          s' = absorbDuplexSponge s ([1, 2, 3] :: [Word8])
          (out1, _) = squeezeDuplexSponge s 32
          (out2, _) = squeezeDuplexSponge s' 32
      assertBool "absorbing should change output" (out1 /= out2)
  , testCase "squeeze advances state" $ do
      let s = newDuplexSponge "test-iv" :: Shake128Sponge
          (out1, s') = squeezeDuplexSponge s 32
          (out2, _) = squeezeDuplexSponge s' 32
      assertBool "consecutive squeezes should produce different output" (out1 /= out2)
  ]
