-- |
-- Module: Crypto.LinearMap
--
-- The linear map interface, as described in Section 2.2.2 ("Linear map") of
-- the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- A linear map takes a witness (an array of scalars from the scalar field)
-- and maps it to an array of group elements via matrix-vector multiplication
-- using elliptic curve scalar multiplication. Since the matrix is oftentimes
-- sparse, it is stored in Yale sparse matrix format using 'LinearCombination'
-- entries that maintain index pairs rather than dense matrices.
module Crypto.LinearMap
  ( LinearCombination(..)
  , LinearMap(..)
  , applyLinearMap
  , LinearRelation(..)
  , allocateScalars
  ) where

import Crypto.PrimeOrderGroup

-- | A single linear combination specifying which witness scalars and group
-- elements participate in a multi-scalar multiplication, as defined in
-- Section 2.2.2 ("Linear map") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- During evaluation, the scalars at 'scalarIndices' are paired with the
-- group elements at 'elementIndices' and combined via multi-scalar
-- multiplication to produce a single group element.
data LinearCombination = LinearCombination
  { -- | Indices into the witness scalar array.
    --
    -- Corresponds to @scalar_indices@ in the spec.
    scalarIndices :: [Int],
    -- | Indices into the group element array stored in the 'LinearMap'.
    --
    -- Corresponds to @element_indices@ in the spec.
    elementIndices :: [Int]
  }

-- | A linear map from witness scalars to group elements, as defined in
-- Section 2.2.2 ("Linear map") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- The map is represented as a sparse matrix in Yale format: each
-- 'LinearCombination' entry describes one row of the matrix, specifying
-- which scalar and group-element indices participate in the corresponding
-- multi-scalar multiplication.
data LinearMap g = LinearMap
  { -- | The sparse matrix rows, each describing a single multi-scalar
    -- multiplication.
    --
    -- Corresponds to @linear_combinations@ in the spec.
    linearCombinations :: [LinearCombination],
    -- | The group elements referenced by index from each
    -- 'LinearCombination'.
    --
    -- Corresponds to @group_elements@ in the spec.
    groupElements :: [g],
    -- | The number of witness scalars accepted by this map.
    --
    -- Corresponds to @num_scalars@ in the spec.
    numScalars :: Int,
    -- | The number of group elements produced by this map.
    --
    -- Corresponds to @num_elements@ in the spec.
    numElements :: Int
  }

-- | Evaluates the linear map on a witness, producing group elements.
--
-- Corresponds to @map(witness)@ in the spec. The function takes the
-- map itself and the witness (as a list of group elements derived from
-- scalars) and returns the image of the witness under the linear map.
applyLinearMap  :: Group g => LinearMap g -> [GroupScalar g] -> [g]
applyLinearMap lm ss = map (\lc -> applyLinearCombination lm lc ss) $ linearCombinations lm

applyLinearCombination :: Group g => LinearMap g -> LinearCombination -> [GroupScalar g] -> g
applyLinearCombination lm lc ss =
  foldl groupAdd groupIdentity
    [ groupScalarMul (groupElements lm !! ei) (ss !! si)
    | (si, ei) <- zip (scalarIndices lc) (elementIndices lc)
    ]

data LinearRelation g = LinearRelation
  { linearMap :: LinearMap g,
    image :: [g]
  }


allocateScalars :: Group g => LinearRelation g -> Int -> (LinearRelation g, [Int])
allocateScalars lr n =  
    let lm   = linearMap lr in
    let start  = numScalars lm in
    let scalars  = take n [start ..] in
    let lm'    = lm { numScalars = start + n } in
    let lr'    = lr { linearMap = lm' }
  in (lr', scalars)

-- allocateElements :: Group g => LinearRelation g -> Int -> (LinearRelation g, [Int])