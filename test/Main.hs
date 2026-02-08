module Main (main) where

import Test.Tasty

import qualified Test.Crypto.Sigma.Curve25519 as Curve25519
import qualified Test.Crypto.Sigma.Shake128 as Shake128
import qualified Test.Crypto.Sigma.Protocol as Protocol
import qualified Test.Crypto.Sigma.FiatShamir as FiatShamir

main :: IO ()
main = defaultMain $ testGroup "sigma-hs"
  [ Curve25519.tests
  , Shake128.tests
  , Protocol.tests
  , FiatShamir.tests
  ]
