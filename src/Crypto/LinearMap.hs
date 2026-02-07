data LinearCombination
  = LinearCombination {scalarIndices :: [Int], elementIndices :: [Int]}

data LinearMap g
  = LinearMap {linearCombinations :: [LinearCombination], groupElements :: [g], numScalars :: Int, numElements :: Int, applyMap :: (LinearMap g, [g]) -> [g]}