{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

-- |
-- Module: Crypto.Sigma.Protocol
--
-- Core sigma protocol operations, as described in Section 2 of the
-- [Sigma Protocols draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html).
--
-- A sigma protocol is a three-move interactive proof of knowledge for
-- linear relations over prime-order groups. The prover commits to random
-- nonces, receives a challenge, and responds in a way that convinces the
-- verifier of knowledge of the witness without revealing it.
module Crypto.Sigma.Protocol
  ( ProverState(..)
  , SchnorrProof(..)
  , Commitment
  , Response
  , Challenge
  , newSchnorrProof
  , proverCommit
  , proverResponse
  , verifier
  , simulateResponse
  , simulateCommitment
  , serializeCommitment
  , serializeResponse
  , deserializeCommitment
  , deserializeResponse
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Vector as V

import Crypto.Sigma.Error (DeserializeError(..))
import Crypto.Sigma.Group
import Crypto.Sigma.Scalar
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Random (MonadRandom)

-- | Prover's internal state between the commit and response phases.
data ProverState s = ProverState
  { -- | The witness scalars the prover is proving knowledge of.
    psWitness :: !(V.Vector s)
    -- | The random nonces generated during the commit phase.
  , psNonces  :: !(V.Vector s)
  } deriving (Show)

-- | A Schnorr proof statement wrapping a 'LinearRelation'.
newtype SchnorrProof g = SchnorrProof
  { spRelation :: LinearRelation g
  } deriving (Show)

-- | The commitment sent by the prover in the first move.
type Commitment g = V.Vector g

-- | The response sent by the prover in the third move.
type Response s = V.Vector s

-- | The challenge sent by the verifier in the second move.
type Challenge s = s

-- | Construct a 'SchnorrProof' from a 'LinearRelation'.
newSchnorrProof :: LinearRelation g -> SchnorrProof g
newSchnorrProof = SchnorrProof

-- | Prover's first move: generate random nonces and compute the commitment.
--
-- Given a proof statement and the witness, generates random nonces and
-- computes @commitment = linear_map(nonces)@.
proverCommit :: forall g m. (Group g, MonadRandom m)
             => SchnorrProof g
             -> V.Vector (GroupScalar g)
             -> m (ProverState (GroupScalar g), Commitment g)
proverCommit proof witness = do
  let lm = lrLinearMap (spRelation proof)
      n = numScalars lm
  nonces <- V.replicateM n scalarRandom
  let commitment = applyLinearMap lm nonces
  return (ProverState { psWitness = witness, psNonces = nonces }, commitment)

-- | Prover's third move: compute the response from nonces, witness, and challenge.
--
-- Computes @response[i] = nonces[i] + witness[i] * challenge@.
proverResponse :: Group g
               => SchnorrProof g
               -> ProverState (GroupScalar g)
               -> Challenge (GroupScalar g)
               -> Response (GroupScalar g)
proverResponse _proof st challenge =
  V.zipWith (\nonce w -> nonce .+. (w .*. challenge)) (psNonces st) (psWitness st)

-- | Verifier's check: verify that the commitment, challenge, and response
-- are consistent with the proof statement.
--
-- Checks @linear_map(response)[i] == commitment[i] + image[i] * challenge@
-- for each constraint.
verifier :: Group g
         => SchnorrProof g
         -> Commitment g
         -> Challenge (GroupScalar g)
         -> Response (GroupScalar g)
         -> Bool
verifier proof commitment challenge response =
  let lr = spRelation proof
      lm = lrLinearMap lr
      lhs = applyLinearMap lm response
      rhs = V.zipWith (\ci ii -> ci |+| (ii |*| challenge)) commitment (lrImageElements lr)
  in lhs == rhs

-- | Simulator: generate a random response vector.
simulateResponse :: forall g m. (Group g, MonadRandom m)
                 => SchnorrProof g
                 -> m (Response (GroupScalar g))
simulateResponse proof =
  let n = numScalars (lrLinearMap (spRelation proof))
  in V.replicateM n scalarRandom

-- | Simulator: compute the commitment from a response and challenge.
--
-- Computes @commitment[i] = linear_map(response)[i] - image[i] * challenge@.
simulateCommitment :: Group g
                   => SchnorrProof g
                   -> Response (GroupScalar g)
                   -> Challenge (GroupScalar g)
                   -> Commitment g
simulateCommitment proof response challenge =
  let lr = spRelation proof
      lm = lrLinearMap lr
      mapResult = applyLinearMap lm response
  in V.zipWith (\mi ii -> mi |-| (ii |*| challenge)) mapResult (lrImageElements lr)

-- | Serialize a commitment to a 'ByteString' by concatenating the
-- serialized group elements.
serializeCommitment :: Group g => Commitment g -> ByteString
serializeCommitment = BS.concat . V.toList . V.map serializeElement

-- | Serialize a response to a 'ByteString' by concatenating the
-- serialized scalars.
serializeResponse :: Group g => Response (GroupScalar g) -> ByteString
serializeResponse = BS.concat . V.toList . V.map serializeScalar

-- | Deserialize a commitment from a 'ByteString', splitting it into
-- chunks of 'elementSize' bytes and deserializing each.
deserializeCommitment :: forall g. Group g
                      => Int
                      -> ByteString
                      -> Either DeserializeError (Commitment g)
deserializeCommitment nElements bs =
  let size = elementSize @g
      chunks = chunkBS size bs
  in if length chunks /= nElements
     then Left (DeserializeError "incorrect commitment length")
     else fmap V.fromList (traverse deserializeElement chunks)

-- | Deserialize a response from a 'ByteString', splitting it into
-- chunks of 'scalarSize' bytes and deserializing each.
deserializeResponse :: forall s. Scalar s
                    => Int
                    -> ByteString
                    -> Either DeserializeError (Response s)
deserializeResponse nScalars bs =
  let size = scalarSize @s
      chunks = chunkBS size bs
  in if length chunks /= nScalars
     then Left (DeserializeError "incorrect response length")
     else fmap V.fromList (traverse deserializeScalar chunks)

chunkBS :: Int -> ByteString -> [ByteString]
chunkBS size bs
  | BS.null bs = []
  | otherwise  = let (h, t) = BS.splitAt size bs in h : chunkBS size t
