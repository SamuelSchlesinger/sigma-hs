module Crypto.LinearMap where

data LinearCombination
  = LinearCombination {scalarIndices :: [Int], elementIndices :: [Int]}

data LinearMap g
  = LinearMap {linearCombinations :: [LinearCombination], groupElements :: [g], numScalars :: Int, numElements :: Int, witnessToGroupElemMap :: (LinearMap g, [g]) -> [g]}