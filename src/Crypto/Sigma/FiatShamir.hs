{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

-- |
-- Module: Crypto.Sigma.FiatShamir
--
-- __This library has not been independently audited. Use at your own risk.__
--
-- Non-interactive Fiat-Shamir transformation for sigma protocols, as
-- described in the
-- [Fiat-Shamir draft](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/#go.draft-irtf-cfrg-fiat-shamir.html).
--
-- The transformation replaces the verifier's random challenge with a hash
-- of the transcript (instance label, commitment, etc.) computed via a
-- duplex sponge, yielding a non-interactive proof.
--
-- Two proof formats are provided:
--
-- * __Compact__ ('prove' / 'verify'): the proof is @challenge || response@.
--   Verification recomputes the commitment from the response and challenge,
--   then checks that re-hashing produces the same challenge.
--
-- * __Batchable__ ('proveBatchable' / 'verifyBatchable'): the proof is
--   @commitment || response@. Verification recomputes the challenge from
--   the commitment and checks the sigma protocol relation directly. This
--   format supports batch verification.
module Crypto.Sigma.FiatShamir
  ( prove
  , verify
  , proveBatchable
  , verifyBatchable
  , makeIV
  , i2osp
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)
import qualified Data.Vector as V

import Crypto.Sigma.DuplexSponge
import Crypto.Sigma.Error (DeserializeError)
import Crypto.Sigma.Group
import Crypto.Sigma.LinearMap
import Crypto.Sigma.Protocol
import Crypto.Sigma.Random (MonadRandom)
import Crypto.Sigma.Scalar

-- | Construct the initialization vector for the Fiat-Shamir sponge.
-- Matches sigma-rs's @initialize_sponge@:
-- 1. Use protocol_id directly as the sponge IV
-- 2. Absorb length-prefixed session_id
makeIV :: forall sponge. (DuplexSponge sponge, Unit sponge ~ Word8)
       => ByteString -> ByteString -> sponge
makeIV protocolId sessionId =
  let s0 = newDuplexSponge protocolId
      s1 = absorbDuplexSponge s0 (BS.unpack (lengthPrefixed sessionId))
  in s1

-- | Initialize the Fiat-Shamir codec by absorbing the length-prefixed
-- instance label into the sponge.
initCodec :: (DuplexSponge sponge, Unit sponge ~ Word8)
          => sponge -> ByteString -> sponge
initCodec sponge instanceLabel =
  absorbDuplexSponge sponge (BS.unpack (lengthPrefixed instanceLabel))

-- | Absorb a prover's commitment into the sponge.
proverMessage :: (DuplexSponge sponge, Unit sponge ~ Word8, Group g)
              => sponge -> Commitment g -> sponge
proverMessage sponge commitment =
  absorbDuplexSponge sponge (BS.unpack (serializeCommitment commitment))

-- | Squeeze a verifier challenge from the sponge. Squeezes
-- @scalarSize + 16@ bytes and reduces them to a near-uniform scalar.
verifierChallenge :: forall s sponge. (DuplexSponge sponge, Unit sponge ~ Word8, Scalar s)
                  => sponge -> (s, sponge)
verifierChallenge sponge =
  let squeezeLen = scalarSize @s + 16
      (bytes, sponge') = squeezeDuplexSponge sponge squeezeLen
      challenge = scalarFromUniformBytes (BS.pack bytes)
  in (challenge, sponge')

-- | Produce a non-interactive proof in compact format (challenge || response).
prove :: forall g sponge m.
         ( Group g, DuplexSponge sponge, Unit sponge ~ Word8, MonadRandom m )
      => sponge
      -> SchnorrProof g
      -> V.Vector (GroupScalar g)
      -> m ByteString
prove sponge proof witness = do
  let lr = spRelation proof
      label = getInstanceLabel lr
      codec0 = initCodec sponge label
  (st, commitment) <- proverCommit proof witness
  let codec1 = proverMessage @sponge @g codec0 commitment
      (challenge, _codec2) = verifierChallenge @(GroupScalar g) codec1
      response = proverResponse proof st challenge
  return (serializeScalar challenge <> serializeResponse @g response)

-- | Verify a non-interactive proof in compact format.
verify :: forall g sponge.
          ( Group g, DuplexSponge sponge, Unit sponge ~ Word8 )
       => sponge
       -> SchnorrProof g
       -> ByteString
       -> Either DeserializeError Bool
verify sponge proof proofBytes = do
  let lr = spRelation proof
      lm = lrLinearMap lr
      nScalars_ = numScalars lm
      nConstraints_ = numConstraints lm
      (challengeBS, responseBS) = BS.splitAt (scalarSize @(GroupScalar g)) proofBytes
  challenge <- deserializeScalar @(GroupScalar g) challengeBS
  response <- deserializeResponse @(GroupScalar g) nScalars_ responseBS
  let commitment = simulateCommitment proof response challenge
      label = getInstanceLabel lr
      codec0 = initCodec sponge label
      codec1 = proverMessage @sponge @g codec0 commitment
      (challenge', _codec2) = verifierChallenge @(GroupScalar g) codec1
  if V.length commitment /= nConstraints_
    then return False
    else return (challenge == challenge')

-- | Produce a non-interactive proof in batchable format (commitment || response).
proveBatchable :: forall g sponge m.
                  ( Group g, DuplexSponge sponge, Unit sponge ~ Word8, MonadRandom m )
               => sponge
               -> SchnorrProof g
               -> V.Vector (GroupScalar g)
               -> m ByteString
proveBatchable sponge proof witness = do
  let lr = spRelation proof
      label = getInstanceLabel lr
      codec0 = initCodec sponge label
  (st, commitment) <- proverCommit proof witness
  let codec1 = proverMessage @sponge @g codec0 commitment
      (challenge, _codec2) = verifierChallenge @(GroupScalar g) codec1
      response = proverResponse proof st challenge
  return (serializeCommitment @g commitment <> serializeResponse @g response)

-- | Verify a non-interactive proof in batchable format.
verifyBatchable :: forall g sponge.
                   ( Group g, DuplexSponge sponge, Unit sponge ~ Word8 )
                => sponge
                -> SchnorrProof g
                -> ByteString
                -> Either DeserializeError Bool
verifyBatchable sponge proof proofBytes = do
  let lr = spRelation proof
      lm = lrLinearMap lr
      eSize = elementSize @g
      nConstraints_ = numConstraints lm
      nScalars_ = numScalars lm
      commitLen = nConstraints_ * eSize
      (commitBS, responseBS) = BS.splitAt commitLen proofBytes
  commitment <- deserializeCommitment @g nConstraints_ commitBS
  response <- deserializeResponse @(GroupScalar g) nScalars_ responseBS
  let label = getInstanceLabel lr
      codec0 = initCodec sponge label
      codec1 = proverMessage @sponge @g codec0 commitment
      (challenge, _codec2) = verifierChallenge @(GroupScalar g) codec1
  return (verifier proof commitment challenge response)

-- Helpers

-- | Big-endian encoding of a non-negative integer in @n@ bytes, per
-- RFC 3447 (I2OSP: Integer-to-Octet-String Primitive).
i2osp :: Int -> Int -> ByteString
i2osp n val =
  let bytes = map (\i -> fromIntegral (val `div` (256 ^ (n - 1 - i)) `mod` 256)) [0..n-1]
  in BS.pack bytes

-- | Prepend a 4-byte big-endian length prefix to a 'ByteString'.
lengthPrefixed :: ByteString -> ByteString
lengthPrefixed bs = i2osp 4 (BS.length bs) <> bs
