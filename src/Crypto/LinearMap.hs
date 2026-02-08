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
  , LinearRelation(..)
  , applyLinearMap
  , emptyLinearRelation
  , allocateScalars
  , allocateElements
  , appendEquation
  , setElements
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
    scalarIndices :: [Int]
    -- | Indices into the group element array stored in the 'LinearMap'.
    --
    -- Corresponds to @element_indices@ in the spec.
  , elementIndices :: [Int]
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
    linearCombinations :: [LinearCombination]
    -- | The group elements referenced by index from each
    -- 'LinearCombination'.
    --
    -- Corresponds to @group_elements@ in the spec.
  , groupElements :: [g]
    -- | The number of witness scalars accepted by this map.
    --
    -- Corresponds to @num_scalars@ in the spec.
  , numScalars :: Int
    -- | The number of group elements produced by this map.
    --
    -- Corresponds to @num_elements@ in the spec.
  , numElements :: Int
  }

-- | A linear relation encodes a proof statement of the form
-- @linear_map(witness) = image@, as defined in Section 2.2.3
-- ("Statements for linear relations") of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- It stores a 'LinearMap' being built incrementally and the image — the
-- target group elements that the linear map must produce when applied to
-- the witness.
data LinearRelation g = LinearRelation
  { -- | The linear map under construction.
    --
    -- Corresponds to @linear_map@ in the spec.
    lrLinearMap :: LinearMap g
    -- | The target group elements that the linear map must produce.
    --
    -- Corresponds to @image@ in the spec.
  , lrImage :: [g]
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

-- | An empty 'LinearRelation' with no scalars, elements, or constraints
-- allocated.
emptyLinearRelation :: LinearRelation g
emptyLinearRelation = LinearRelation
  { lrLinearMap = LinearMap
      { linearCombinations = []
      , groupElements = []
      , numScalars = 0
      , numElements = 0
      }
  , lrImage = []
  }

-- | Allocate @n@ new scalar variables, returning the updated relation and
-- the indices of the newly allocated scalars.
--
-- Corresponds to @allocate_scalars()@ in the spec.
allocateScalars :: LinearRelation g -> Int -> (LinearRelation g, [Int])
allocateScalars lr n =
  let lm = lrLinearMap lr
      start = numScalars lm
      indices = [start .. start + n - 1]
      lm' = lm { numScalars = start + n }
  in (lr { lrLinearMap = lm' }, indices)

-- | Allocate @n@ new group element slots, returning the updated relation
-- and the indices of the newly allocated slots. The slots are
-- initialized to the group identity and should be filled using
-- 'setElements'.
--
-- Corresponds to @allocate_elements()@ in the spec.
allocateElements :: Group g => LinearRelation g -> Int -> (LinearRelation g, [Int])
allocateElements lr n =
  let lm = lrLinearMap lr
      start = numElements lm
      indices = [start .. start + n - 1]
      lm' = lm { numElements = start + n
                , groupElements = groupElements lm ++ replicate n groupIdentity
                }
  in (lr { lrLinearMap = lm' }, indices)

-- | Append a constraint equation to the linear relation, stating that a
-- particular linear combination of witness scalars and basis group
-- elements must equal the given target group element.
--
-- The right-hand side is a list of @(scalarIndex, elementIndex)@ pairs
-- describing the linear combination. The left-hand side is the target
-- group element that the combination must produce.
--
-- Corresponds to @append_equation()@ in the spec.
appendEquation :: LinearRelation g -> g -> [(Int, Int)] -> LinearRelation g
appendEquation lr lhs rhs = lr
  { lrLinearMap = lm { linearCombinations = linearCombinations lm ++ [lc] }
  , lrImage = lrImage lr ++ [lhs]
  }
  where
    lm = lrLinearMap lr
    lc = LinearCombination
      { scalarIndices = map fst rhs
      , elementIndices = map snd rhs
      }

-- | Set group element values at the specified indices in the internal
-- 'LinearMap'. These are the basis elements referenced by index from
-- each 'LinearCombination'.
--
-- Corresponds to @set_elements()@ in the spec.
setElements :: LinearRelation g -> [(Int, g)] -> LinearRelation g
setElements lr updates = lr { lrLinearMap = lm { groupElements = newElems } }
  where
    lm = lrLinearMap lr
    newElems = foldl setAt (groupElements lm) updates
    setAt xs (i, x) = take i xs ++ [x] ++ drop (i + 1) xs
