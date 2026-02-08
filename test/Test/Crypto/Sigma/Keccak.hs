{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.Sigma.Keccak (tests) where

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Crypto.Sigma.DuplexSponge
import Crypto.Sigma.Keccak (KeccakSponge)

-- | Convert a list of Word8 to a hex string for comparison.
toHex :: [Word8] -> String
toHex = concatMap (\b -> let (hi, lo) = b `divMod` 16 in [hexDigit hi, hexDigit lo])
  where hexDigit n | n < 10    = toEnum (fromIntegral n + fromEnum '0')
                   | otherwise = toEnum (fromIntegral n - 10 + fromEnum 'a')

tests :: TestTree
tests = testGroup "Keccak"
  [ testCase "determinism" $ do
      let s1 = newDuplexSponge "test-iv-for-keccak-sponge-determinism-test!!!!!!!!!!!!!!!!!!!!!!!" :: KeccakSponge
          s2 = newDuplexSponge "test-iv-for-keccak-sponge-determinism-test!!!!!!!!!!!!!!!!!!!!!!!" :: KeccakSponge
          (out1, _) = squeezeDuplexSponge s1 32
          (out2, _) = squeezeDuplexSponge s2 32
      out1 @?= out2
  , testCase "different IVs produce different output" $ do
      let iv1 = BS.replicate 64 0x01
          iv2 = BS.replicate 64 0x02
          s1 = newDuplexSponge iv1 :: KeccakSponge
          s2 = newDuplexSponge iv2 :: KeccakSponge
          (out1, _) = squeezeDuplexSponge s1 32
          (out2, _) = squeezeDuplexSponge s2 32
      assertBool "different IVs should produce different output" (out1 /= out2)
  , testCase "absorb changes output" $ do
      let iv = BS.replicate 64 0xAA
          s = newDuplexSponge iv :: KeccakSponge
          s' = absorbDuplexSponge s ([1, 2, 3] :: [Word8])
          (out1, _) = squeezeDuplexSponge s 32
          (out2, _) = squeezeDuplexSponge s' 32
      assertBool "absorbing should change output" (out1 /= out2)
  , testCase "absorb associativity (sigma-rs test vector)" $ do
      -- Test vector from sigma-rs: tag = 64-byte domain separator,
      -- absorb "hello world", squeeze 32 bytes
      let tag = "absorb-associativity-domain-----absorb-associativity-domain-----" :: BS.ByteString
          expected = "efc1c34f94c0d9cfe051561f8206543056ce660fd17834b2eeb9431a4c65bc77"

          -- Absorb all at once
          s1 = newDuplexSponge tag :: KeccakSponge
          s1' = absorbDuplexSponge s1 (BS.unpack ("hello world" :: BS.ByteString))
          (out1, _) = squeezeDuplexSponge s1' 32

          -- Absorb in two parts
          s2 = newDuplexSponge tag :: KeccakSponge
          s2' = absorbDuplexSponge s2 (BS.unpack ("hello" :: BS.ByteString))
          s2'' = absorbDuplexSponge s2' (BS.unpack (" world" :: BS.ByteString))
          (out2, _) = squeezeDuplexSponge s2'' 32

      -- Both should produce the same output
      assertEqual "absorb should be associative" out1 out2
      -- And match the known test vector
      assertEqual "should match sigma-rs test vector" expected (toHex out1)
  ]
