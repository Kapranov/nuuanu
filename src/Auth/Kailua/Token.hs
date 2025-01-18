{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE RecordWildCards    #-}
{-|
  Module      : Auth.Kailua.Token
  Copyright   : updated © Oleg G.kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  Module defining the main biscuit-related operations
-}
module Auth.Kailua.Token (Kailua) where

import           Auth.Kailua.Crypto                  ( PublicKey
                                                     , SecretKey
                                                     , Signature
                                                     , SignedBlock
                                                     , getSignatureProof
                                                     , sigBytes
                                                     , sign3rdPartyBlock
                                                     , signBlock
                                                     , signExternalBlock
                                                     , skBytes
                                                     , toPublic
                                                     , verifyBlocks
                                                     , verifyExternalSig
                                                     , verifySecretProof
                                                     , verifySignatureProof
                                                     )
import           Auth.Kailua.Datalog.AST             ( Authorizer
                                                     , Block
                                                     , Query
                                                     , toEvaluation
                                                     )
import           Auth.Kailua.Datalog.Executo         ( Bindings
                                                     , ExecutionError
                                                     , Limits
                                                     , defaultLimits
                                                     )
import           Auth.Kailua.Datalog.ScopedExecutor  ( AuthorizationSuccess
                                                     , collectWorld
                                                     , queryAvailableFacts
                                                     , queryGeneratedFacts
                                                     , runAuthorizerWithLimits
                                                     )
import qualified Auth.Kailua.Proto                   as PB
import           Auth.Kailua.ProtoBufAdapter         ( blockToPb
                                                     , pbToBlock
                                                     , pbToProof
                                                     , pbToSignedBlock
                                                     , pbToThirdPartyBlockContents
                                                     , pbToThirdPartyBlockRequest
                                                     , signedBlockToPb
                                                     , thirdPartyBlockContentsToPb
                                                     , thirdPartyBlockRequestToPb
                                                     )
import           Auth.Kailua.Symbols
import           Control.Monad                       (join, unless, when)
import           Control.Monad.State                 (lift, mapStateT,
                                                      runStateT)
import           Data.Bifunctor                      (first)
import           Data.ByteString                     (ByteString)
import qualified Data.ByteString.Base64.URL          as B64
import           Data.List.NonEmpty                  (NonEmpty ((:|)))
import qualified Data.List.NonEmpty                  as NE
import           Data.Set                            (Set)
import qualified Data.Set                            as Set

type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, Signature, PublicKey, Maybe (Signature, PublicKey))

newtype Open = Open SecretKey
  deriving stock (Eq, Show)

newtype Sealed = Sealed Signature
  deriving stock (Eq, Show)

newtype Verified = Verified PublicKey
  deriving stock (Eq, Show)

data OpenOrSealed
  = SealedProof Signature
  | OpenProof SecretKey
  deriving (Eq, Show)

data Unverified = Unverified
  deriving stock (Eq, Show)

data Kailua proof check
  = Kailua
  { rootKeyId  :: Maybe Int
  , symbols    :: Symbols
  , authority  :: ParsedSignedBlock
  , blocks     :: [ParsedSignedBlock]
  , proof      :: proof
  , proofCheck :: check
  }
  deriving (Eq, Show)

class KailuaProof a
  where
    toPossibleProofs :: a -> OpenOrSealed

instance KailuaProof OpenOrSealed
  where
    toPossibleProofs = id
instance KailuaProof Sealed
  where
    toPossibleProofs (Sealed sig) = SealedProof sig
instance KailuaProof Open
  where
    toPossibleProofs (Open sk) = OpenProof sk
