-- |
-- Module: Crypto.Sigma.LinearMap
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
--
-- The 'LinearRelation' building functions ('allocateScalars',
-- 'allocateElements', 'appendEquation', 'setElements') use the 'State'
-- monad to thread the relation being constructed.
module Crypto.Sigma.LinearMap
  ( LinearCombination(..)
  , LinearMap(..)
  , LinearRelation(..)
  , applyLinearMap
  , numConstraints
  , emptyLinearRelation
  , buildLinearRelation
  , buildLinearRelation_
  , allocateScalars
  , allocateElements
  , appendEquation
  , setElements
  , lrImageElements
  , getInstanceLabel
  ) where

import Control.Monad.Trans.State.Strict (State, get, put, modify, runState)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Vector as V

import Crypto.Sigma.Group

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
    scalarIndices :: !(V.Vector Int)
    -- | Indices into the group element array stored in the 'LinearMap'.
    --
    -- Corresponds to @element_indices@ in the spec.
  , elementIndices :: !(V.Vector Int)
  } deriving (Show)

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
    linearCombinations :: !(V.Vector LinearCombination)
    -- | The group elements referenced by index from each
    -- 'LinearCombination'.
    --
    -- Corresponds to @group_elements@ in the spec.
  , groupElements :: !(V.Vector g)
    -- | The number of witness scalars accepted by this map.
    --
    -- Corresponds to @num_scalars@ in the spec.
  , numScalars :: !Int
    -- | The number of group elements produced by this map.
    --
    -- Corresponds to @num_elements@ in the spec.
  , numElements :: !Int
  } deriving (Show)

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
    lrLinearMap :: !(LinearMap g)
    -- | Indices into @groupElements@ of the linear map, representing the
    -- target group elements that the linear map must produce.
    --
    -- Corresponds to @image@ in the spec.
  , lrImage :: !(V.Vector Int)
  } deriving (Show)

-- | Evaluates the linear map on a witness, producing group elements.
--
-- Corresponds to @map(witness)@ in the spec. The function takes the
-- map itself and the witness (as a vector of scalars) and returns the
-- image of the witness under the linear map.
applyLinearMap :: Group g => LinearMap g -> V.Vector (GroupScalar g) -> V.Vector g
applyLinearMap lm ss = V.map (\lc -> applyLinearCombination lm lc ss) $ linearCombinations lm

applyLinearCombination :: Group g => LinearMap g -> LinearCombination -> V.Vector (GroupScalar g) -> g
applyLinearCombination lm lc ss =
  let sIndices = scalarIndices lc
      eIndices = elementIndices lc
      scalars = V.map (ss V.!) sIndices
      elements = V.map (groupElements lm V.!) eIndices
  in msm scalars elements

-- | The number of constraint equations in a linear map.
numConstraints :: LinearMap g -> Int
numConstraints = V.length . linearCombinations

-- | An empty 'LinearRelation' with no scalars, elements, or constraints
-- allocated.
emptyLinearRelation :: LinearRelation g
emptyLinearRelation = LinearRelation
  { lrLinearMap = LinearMap
      { linearCombinations = V.empty
      , groupElements = V.empty
      , numScalars = 0
      , numElements = 0
      }
  , lrImage = V.empty
  }

-- | Run a 'LinearRelation' builder from an empty relation, returning
-- both the builder's result and the final relation.
buildLinearRelation :: State (LinearRelation g) a -> (a, LinearRelation g)
buildLinearRelation = flip runState emptyLinearRelation

-- | Run a 'LinearRelation' builder from an empty relation, discarding
-- the builder's result.
buildLinearRelation_ :: State (LinearRelation g) a -> LinearRelation g
buildLinearRelation_ = snd . buildLinearRelation

-- | Allocate @n@ new scalar variables, returning the indices of the
-- newly allocated scalars.
--
-- Corresponds to @allocate_scalars()@ in the spec.
allocateScalars :: Int -> State (LinearRelation g) (V.Vector Int)
allocateScalars n = do
  lr <- get
  let lm = lrLinearMap lr
      start = numScalars lm
      indices = V.fromList [start .. start + n - 1]
  put lr { lrLinearMap = lm { numScalars = start + n } }
  return indices

-- | Allocate @n@ new group element slots, returning the indices of the
-- newly allocated slots. The slots are initialized to the group identity
-- and should be filled using 'setElements'.
--
-- Corresponds to @allocate_elements()@ in the spec.
allocateElements :: Group g => Int -> State (LinearRelation g) (V.Vector Int)
allocateElements n = do
  lr <- get
  let lm = lrLinearMap lr
      start = numElements lm
      indices = V.fromList [start .. start + n - 1]
      lm' = lm { numElements = start + n
                , groupElements = groupElements lm V.++ V.replicate n groupIdentity
                }
  put lr { lrLinearMap = lm' }
  return indices

-- | Append a constraint equation to the linear relation, stating that a
-- particular linear combination of witness scalars and basis group
-- elements must equal the group element at the given index.
--
-- The right-hand side is a list of @(scalarIndex, elementIndex)@ pairs
-- describing the linear combination. The left-hand side is an index into
-- the @groupElements@ array.
--
-- Corresponds to @append_equation()@ in the spec.
appendEquation :: Int -> [(Int, Int)] -> State (LinearRelation g) ()
appendEquation lhsIdx rhs = modify $ \lr ->
  let lm = lrLinearMap lr
      lc = LinearCombination
        { scalarIndices = V.fromList (map fst rhs)
        , elementIndices = V.fromList (map snd rhs)
        }
  in lr { lrLinearMap = lm { linearCombinations = V.snoc (linearCombinations lm) lc }
        , lrImage = V.snoc (lrImage lr) lhsIdx
        }

-- | Set group element values at the specified indices in the internal
-- 'LinearMap'. These are the basis elements referenced by index from
-- each 'LinearCombination'.
--
-- Corresponds to @set_elements()@ in the spec.
setElements :: [(Int, g)] -> State (LinearRelation g) ()
setElements updates = modify $ \lr ->
  let lm = lrLinearMap lr
      newElems = groupElements lm V.// updates
  in lr { lrLinearMap = lm { groupElements = newElems } }

-- | Resolve image indices to actual group elements.
lrImageElements :: LinearRelation g -> V.Vector g
lrImageElements lr = V.map (groupElements (lrLinearMap lr) V.!) (lrImage lr)

-- | Compute a canonical label for a linear relation, for use in
-- Fiat-Shamir domain separation. Serializes all group elements and
-- the sparse matrix structure.
getInstanceLabel :: Group g => LinearRelation g -> ByteString
getInstanceLabel lr =
  let lm = lrLinearMap lr
      elems = BS.concat $ V.toList $ V.map serializeElement (groupElements lm)
      image = BS.concat $ V.toList $ V.map (\i -> serializeElement (groupElements lm V.! i)) (lrImage lr)
      combos = BS.concat $ V.toList $ V.map serializeLc (linearCombinations lm)
  in elems <> image <> combos
  where
    serializeLc lc =
      let si = BS.concat $ map (i2osp 4) $ V.toList (scalarIndices lc)
          ei = BS.concat $ map (i2osp 4) $ V.toList (elementIndices lc)
      in i2osp 4 (V.length (scalarIndices lc)) <> si <> ei
    i2osp :: Int -> Int -> ByteString
    i2osp n val =
      let bytes = map (\i -> fromIntegral (val `div` (256 ^ (n - 1 - i)) `mod` 256)) [0..n-1 :: Int]
      in BS.pack bytes
