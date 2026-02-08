{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.Crypto.Sigma.Properties (tests) where

import Test.Tasty
import Test.Tasty.HUnit (testCase, assertBool, assertFailure)
import Test.Tasty.Hedgehog
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import qualified Data.ByteString as BS
import qualified Data.Vector as V

import Crypto.Sigma.Scalar
import Crypto.Sigma.Group
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
import Crypto.Sigma.FiatShamir
import Crypto.Sigma.Shake128 (Shake128Sponge)
import Crypto.Sigma.Curve25519.Ristretto255

-- ── Relation spec (pure, shrinkable) ─────────────────────────────────

data RelationSpec
  = MultiDlog Int          -- n independent discrete logs
  | MultiBaseDLEQ Int      -- 1 scalar, k bases
  | Pedersen               -- 2 scalars, 1 equation with 2 terms
  | GeneralMatrix Int [[Int]]  -- numScalars, eqSpecs (each eq is list of scalar indices)
  deriving (Show)

genRelationSpec :: Gen RelationSpec
genRelationSpec = Gen.choice
  [ MultiDlog <$> Gen.int (Range.linear 1 20)
  , MultiBaseDLEQ <$> Gen.int (Range.linear 2 20)
  , pure Pedersen
  , do numS <- Gen.int (Range.linear 1 15)
       numEqs <- Gen.int (Range.linear 1 15)
       eqs <- Gen.list (Range.singleton numEqs) $
         Gen.list (Range.linear 1 (min numS 8)) $
           Gen.int (Range.linear 0 (numS - 1))
       pure (GeneralMatrix numS eqs)
  ]

-- ── Materialized relation with witness ───────────────────────────────

data MaterializedRelation = MaterializedRelation
  (LinearRelation Ristretto255Point)
  (V.Vector Ristretto255Scalar)

materializeSpec :: RelationSpec -> IO MaterializedRelation
materializeSpec (MultiDlog n) = buildMultiDlog n
materializeSpec (MultiBaseDLEQ k) = buildMultiBaseDLEQ k
materializeSpec Pedersen = buildPedersen
materializeSpec (GeneralMatrix numS eqSpecs) = buildGeneralMatrix numS eqSpecs

-- ── Relation builders ────────────────────────────────────────────────

-- N independent discrete logs: Xi = xi * Gi
buildMultiDlog :: Int -> IO MaterializedRelation
buildMultiDlog n = do
  witnesses <- V.replicateM n (scalarRandom @Ristretto255Scalar)
  bases <- V.replicateM n (groupRandom @Ristretto255Point)
  let images = V.zipWith (\g x -> g |*| x) bases witnesses
      lr = buildLinearRelation_ $ do
        sIdx <- allocateScalars n
        -- each equation needs its base + image = 2 elements per eq
        eIdx <- allocateElements (2 * n)
        setElements $
          [ (eIdx V.! (2 * i), bases V.! i) | i <- [0..n-1] ] ++
          [ (eIdx V.! (2 * i + 1), images V.! i) | i <- [0..n-1] ]
        mapM_ (\i ->
          appendEquation (eIdx V.! (2 * i + 1))
            [(sIdx V.! i, eIdx V.! (2 * i))]
          ) [0..n-1]
  pure (MaterializedRelation lr witnesses)

-- 1 scalar, K bases: Xi = x * Gi
buildMultiBaseDLEQ :: Int -> IO MaterializedRelation
buildMultiBaseDLEQ k = do
  x <- scalarRandom @Ristretto255Scalar
  bases <- V.replicateM k (groupRandom @Ristretto255Point)
  let images = V.map (\g -> g |*| x) bases
      lr = buildLinearRelation_ $ do
        sIdx <- allocateScalars 1
        -- k bases + k images = 2k elements
        eIdx <- allocateElements (2 * k)
        setElements $
          [ (eIdx V.! i, bases V.! i) | i <- [0..k-1] ] ++
          [ (eIdx V.! (k + i), images V.! i) | i <- [0..k-1] ]
        mapM_ (\i ->
          appendEquation (eIdx V.! (k + i))
            [(sIdx V.! 0, eIdx V.! i)]
          ) [0..k-1]
  pure (MaterializedRelation lr (V.singleton x))

-- Pedersen commitment: C = r*H + v*G (2 scalars, 1 equation, 2 terms)
buildPedersen :: IO MaterializedRelation
buildPedersen = do
  r <- scalarRandom @Ristretto255Scalar
  v <- scalarRandom @Ristretto255Scalar
  h <- groupRandom @Ristretto255Point
  let g = groupGenerator @Ristretto255Point
      c = (h |*| r) |+| (g |*| v)
      lr = buildLinearRelation_ $ do
        sIdx <- allocateScalars 2
        eIdx <- allocateElements 3  -- H, G, C
        setElements [(eIdx V.! 0, h), (eIdx V.! 1, g), (eIdx V.! 2, c)]
        appendEquation (eIdx V.! 2)
          [(sIdx V.! 0, eIdx V.! 0), (sIdx V.! 1, eIdx V.! 1)]
  pure (MaterializedRelation lr (V.fromList [r, v]))

-- General sparse matrix: numS scalars, arbitrary equations
buildGeneralMatrix :: Int -> [[Int]] -> IO MaterializedRelation
buildGeneralMatrix numS eqSpecs = do
  witnesses <- V.replicateM numS (scalarRandom @Ristretto255Scalar)
  -- Each equation needs its own set of basis elements (one per term) + one image element
  -- Pre-generate all basis elements
  let totalBases = sum (map length eqSpecs)
      totalElems = totalBases + length eqSpecs  -- bases + images
  allBases <- V.replicateM totalBases (groupRandom @Ristretto255Point)
  -- Compute images by evaluating each equation
  let computeImages _ [] = []
      computeImages baseOff (eq:rest) =
        let nTerms = length eq
            img = V.foldl' groupAdd (groupIdentity @Ristretto255Point)
              (V.fromList [ (allBases V.! (baseOff + t)) |*| (witnesses V.! (eq !! t))
                          | t <- [0..nTerms-1] ])
        in img : computeImages (baseOff + nTerms) rest
      imageList = computeImages 0 eqSpecs
      lr = buildLinearRelation_ $ do
        sIdx <- allocateScalars numS
        eIdx <- allocateElements totalElems
        -- Set basis elements
        let setBases _ [] = pure ()
            setBases off (eq:rest) = do
              let nTerms = length eq
              setElements [ (eIdx V.! (off + t), allBases V.! (off + t)) | t <- [0..nTerms-1] ]
              setBases (off + nTerms) rest
        setBases 0 eqSpecs
        -- Set image elements (they go after all basis elements)
        setElements [ (eIdx V.! (totalBases + i), imageList !! i) | i <- [0..length eqSpecs - 1] ]
        -- Append equations
        let addEqsIdx _ _ [] = pure ()
            addEqsIdx eqI off (eq:rest) = do
              let nTerms = length eq
                  terms = [ (sIdx V.! (eq !! t), eIdx V.! (off + t)) | t <- [0..nTerms-1] ]
              appendEquation (eIdx V.! (totalBases + eqI)) terms
              addEqsIdx (eqI + 1) (off + nTerms) rest
        addEqsIdx 0 0 eqSpecs
  pure (MaterializedRelation lr witnesses)

-- ── Sponge for Fiat-Shamir tests ────────────────────────────────────

sponge :: Shake128Sponge
sponge = makeIV "sigma-protocol-v1" "property-tests"

-- ── Property tests ───────────────────────────────────────────────────

prop_honestInteractiveVerifies :: Property
prop_honestInteractiveVerifies = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr wit <- evalIO (materializeSpec spec)
  let proof = newSchnorrProof lr
  (st, commitment) <- evalIO (proverCommit proof wit)
  challenge <- evalIO (scalarRandom @Ristretto255Scalar)
  let response = proverResponse proof st challenge
  assert (verifier proof commitment challenge response)

prop_honestCompactVerifies :: Property
prop_honestCompactVerifies = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr wit <- evalIO (materializeSpec spec)
  let proof = newSchnorrProof lr
  proofBytes <- evalIO (prove @Ristretto255Point @Shake128Sponge sponge proof wit)
  case verify @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
    Left err -> do
      footnote ("deserialization failed: " ++ show err)
      failure
    Right ok -> assert ok

prop_honestBatchableVerifies :: Property
prop_honestBatchableVerifies = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr wit <- evalIO (materializeSpec spec)
  let proof = newSchnorrProof lr
  proofBytes <- evalIO (proveBatchable @Ristretto255Point @Shake128Sponge sponge proof wit)
  case verifyBatchable @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
    Left err -> do
      footnote ("deserialization failed: " ++ show err)
      failure
    Right ok -> assert ok

prop_wrongWitnessRejects :: Property
prop_wrongWitnessRejects = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr wit <- evalIO (materializeSpec spec)
  let proof = newSchnorrProof lr
      n = V.length wit
  badWit <- evalIO (V.replicateM n (scalarRandom @Ristretto255Scalar))
  (st, commitment) <- evalIO (proverCommit proof badWit)
  challenge <- evalIO (scalarRandom @Ristretto255Scalar)
  let response = proverResponse proof st challenge
  assert (not (verifier proof commitment challenge response))

prop_simulationVerifies :: Property
prop_simulationVerifies = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr _wit <- evalIO (materializeSpec spec)
  let proof = newSchnorrProof lr
  response <- evalIO (simulateResponse proof)
  challenge <- evalIO (scalarRandom @Ristretto255Scalar)
  let commitment = simulateCommitment proof response challenge
  assert (verifier proof commitment challenge response)

prop_instanceLabelDeterministic :: Property
prop_instanceLabelDeterministic = property $ do
  spec <- forAll genRelationSpec
  MaterializedRelation lr _wit <- evalIO (materializeSpec spec)
  let label1 = getInstanceLabel lr
      label2 = getInstanceLabel lr
  label1 === label2
  assert (not (BS.null label1))

-- ── Scaling tests ────────────────────────────────────────────────────

scalingTest :: String -> IO MaterializedRelation -> TestTree
scalingTest name buildRelation = testCase name $ do
  MaterializedRelation lr wit <- buildRelation
  let proof = newSchnorrProof lr

  -- Interactive
  (st, commitment) <- proverCommit proof wit
  challenge <- scalarRandom @Ristretto255Scalar
  let response = proverResponse proof st challenge
  assertBool "interactive" (verifier proof commitment challenge response)

  -- Compact
  proofBytes <- prove @Ristretto255Point @Shake128Sponge sponge proof wit
  case verify @Ristretto255Point @Shake128Sponge sponge proof proofBytes of
    Left err -> assertFailure ("compact deser: " ++ show err)
    Right ok -> assertBool "compact" ok

  -- Batchable
  batchBytes <- proveBatchable @Ristretto255Point @Shake128Sponge sponge proof wit
  case verifyBatchable @Ristretto255Point @Shake128Sponge sponge proof batchBytes of
    Left err -> assertFailure ("batchable deser: " ++ show err)
    Right ok -> assertBool "batchable" ok

-- ── Test tree ────────────────────────────────────────────────────────

tests :: TestTree
tests = testGroup "Properties"
  [ testGroup "property tests"
    [ testProperty "honest interactive verifies" prop_honestInteractiveVerifies
    , testProperty "honest compact verifies" prop_honestCompactVerifies
    , testProperty "honest batchable verifies" prop_honestBatchableVerifies
    , testProperty "wrong witness rejects" prop_wrongWitnessRejects
    , testProperty "simulation verifies" prop_simulationVerifies
    , testProperty "instance label deterministic" prop_instanceLabelDeterministic
    ]
  , testGroup "scaling"
    [ scalingTest "50 independent discrete logs" (buildMultiDlog 50)
    , scalingTest "50-base DLEQ" (buildMultiBaseDLEQ 50)
    , scalingTest "general 20x50 (3 terms each)" $
        buildGeneralMatrix 20 [ [i `mod` 20, (i+7) `mod` 20, (i+13) `mod` 20] | i <- [0..49] ]
    , scalingTest "general 50x100 (2-5 terms each)" $
        buildGeneralMatrix 50 [ take (2 + i `mod` 4) [ (i*j+j) `mod` 50 | j <- [0..] ] | i <- [0..99] ]
    ]
  ]
