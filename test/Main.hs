module Main (main) where

import Test.Tasty

import qualified Test.Crypto.Sigma.Curve25519 as Curve25519
import qualified Test.Crypto.Sigma.Shake128 as Shake128
import qualified Test.Crypto.Sigma.Keccak as Keccak
import qualified Test.Crypto.Sigma.Protocol as Protocol
import qualified Test.Crypto.Sigma.FiatShamir as FiatShamir
import qualified Test.Crypto.Sigma.CrossCompat as CrossCompat

main :: IO ()
main = defaultMain $ testGroup "sigma-proofs"
  [ Curve25519.tests
  , Shake128.tests
  , Keccak.tests
  , Protocol.tests
  , FiatShamir.tests
  , CrossCompat.tests
  ]
