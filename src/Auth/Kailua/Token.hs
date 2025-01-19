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
module Auth.Kailua.Token ( AuthorizedKailua (..)
                         , ExistingBlock
                         , Kailua
                         , KailuaEncoding (..)
                         , KailuaProof (..)
                         , Open
                         , OpenOrSealed
                         , ParseError (..)
                         , ParsedSignedBlock
                         , ParserConfig (..)
                         , Sealed
                         , Unverified
                         , Verified
                         , addBlock
                         , addSignedBlock
                         , applyThirdPartyBlock
                         , asOpen
                         , asSealed
                         , authority
                         , authorizeKailua
                         , authorizeKailuaWithLimits
                         , blocks
                         , checkKailuaSignatures
                         , fromOpen
                         , fromSealed
                         , getRevocationIds
                         , getVerifiedKailuaPublicKey
                         , mkKailua
                         , mkKailuaWith
                         , mkThirdPartyBlock
                         , mkThirdPartyBlockReq
                         , parseKailuaUnverified
                         , parseKailuaWith
                         , proof
                         , proofCheck
                         , queryAuthorizerFacts
                         , queryRawKailuaFacts
                         , rootKeyId
                         , seal
                         , serializeKailua
                         , symbols
                         ) where

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
import           Auth.Kailua.Datalog.Executor        ( Bindings
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

data ParseError
  = InvalidHexEncoding
  | InvalidB64Encoding
  | InvalidProtobufSer Bool String
  | InvalidProtobuf Bool String
  | InvalidSignatures
  | InvalidProof
  | RevokedKailua
  deriving (Eq, Show)

data KailuaWrapper
   = KailuaWrapper
  { wAuthority :: SignedBlock
  , wBlocks    :: [SignedBlock]
  , wProof     :: OpenOrSealed
  , wRootKeyId :: Maybe Int
  }

data KailuaEncoding
  = RawBytes
  | UrlBase64

data ParserConfig m
  = ParserConfig
  { encoding     :: KailuaEncoding
  , isRevoked    :: Set ByteString -> m Bool
  , getPublicKey :: Maybe Int -> PublicKey
  }

data AuthorizedKailua p
  = AuthorizedKailua
  { authorizedKailua     :: Kailua p Verified
  , authorizationSuccess :: AuthorizationSuccess
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

asOpen :: Kailua OpenOrSealed check -> Maybe (Kailua Open check)
asOpen b@Kailua{proof}   = case proof of
  OpenProof p -> Just $ b { proof = Open p }
  _           -> Nothing

asSealed :: Kailua OpenOrSealed check -> Maybe (Kailua Sealed check)
asSealed b@Kailua{proof} = case proof of
  SealedProof p -> Just $ b { proof = Sealed p }
  _             -> Nothing

fromSealed :: Kailua Sealed check -> Kailua OpenOrSealed check
fromSealed b@Kailua{proof = Sealed p } = b { proof = SealedProof p }

fromOpen :: Kailua Open check -> Kailua OpenOrSealed check
fromOpen b@Kailua{proof = Open p } = b { proof = OpenProof p }

queryRawKailuaFactsWithLimits :: Kailua openOrSealed check -> Limits -> Query -> Either String (Set Bindings)
queryRawKailuaFactsWithLimits b@Kailua{authority,blocks} =
  let ePks = externalKeys b
      getBlock ((_, block), _, _, _) = block
      allBlocks = zip [0..] $ getBlock <$> authority : blocks
      (_, sFacts) = foldMap (uncurry collectWorld . fmap (toEvaluation ePks)) allBlocks
  in queryAvailableFacts ePks sFacts

queryRawKailuaFacts :: Kailua openOrSealed check -> Query -> Either String (Set Bindings)
queryRawKailuaFacts b = queryRawKailuaFactsWithLimits b defaultLimits

mkKailua :: SecretKey -> Block -> IO (Kailua Open Verified)
mkKailua = mkKailuaWith Nothing

mkKailuaWith :: Maybe Int -> SecretKey -> Block -> IO (Kailua Open Verified)
mkKailuaWith rootKeyId sk authority = do
  let (authoritySymbols, authoritySerialized) = PB.encodeBlock <$> blockToPb False newSymbolTable authority
  (signedBlock, nextSk) <- signBlock sk authoritySerialized Nothing
  pure Kailua { rootKeyId
              , authority = toParsedSignedBlock authority signedBlock
              , blocks = []
              , symbols = addFromBlock newSymbolTable authoritySymbols
              , proof = Open nextSk
              , proofCheck = Verified $ toPublic sk
              }

addBlock :: Block -> Kailua Open check -> IO (Kailua Open check)
addBlock block b@Kailua{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb False symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized Nothing
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = addFromBlock symbols blockSymbols
           , proof = Open nextSk
           }

addSignedBlock :: SecretKey -> Block -> Kailua Open check -> IO (Kailua Open check)
addSignedBlock eSk block b@Kailua{..} = do
  let (_, blockSerialized) = PB.encodeBlock <$> blockToPb True newSymbolTable block
      lastBlock = NE.last (authority :| blocks)
      (_, _, lastPublicKey, _) = lastBlock
      Open p = proof
  (signedBlock, nextSk) <- signExternalBlock p eSk lastPublicKey blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , proof = Open nextSk
           }

mkThirdPartyBlock' :: SecretKey -> PublicKey -> Block -> (ByteString, Signature, PublicKey)
mkThirdPartyBlock' eSk lastPublicKey block =
  let (_, payload) = PB.encodeBlock <$> blockToPb True newSymbolTable block
      (eSig, ePk) = sign3rdPartyBlock eSk lastPublicKey payload
  in (payload, eSig, ePk)

mkThirdPartyBlock :: SecretKey -> ByteString -> Block -> Either String ByteString
mkThirdPartyBlock eSk req block = do
  previousPk<- pbToThirdPartyBlockRequest =<< PB.decodeThirdPartyBlockRequest req
  pure $ PB.encodeThirdPartyBlockContents . thirdPartyBlockContentsToPb $ mkThirdPartyBlock' eSk previousPk block

mkThirdPartyBlockReq :: Kailua proof check -> ByteString
mkThirdPartyBlockReq Kailua{authority,blocks} =
  let (_, _ , lastPk, _) = NE.last $ authority :| blocks
  in PB.encodeThirdPartyBlockRequest $ thirdPartyBlockRequestToPb lastPk

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk, eSig) = ((serializedBlock, block), sig, pk, eSig)

applyThirdPartyBlock :: Kailua Open check -> ByteString -> Either String (IO (Kailua Open check))
applyThirdPartyBlock b@Kailua{..} contents = do
  (payload, eSig, ePk) <- pbToThirdPartyBlockContents =<< PB.decodeThirdPartyBlockContents contents
  let Open p = proof
      addESig (a,b',c,_) = (a,b',c, Just (eSig, ePk))
      (_, _, lastPk, _) = NE.last $ authority :| blocks
  pbBlock <- PB.decodeBlock payload
  (block, newSymbols) <- (`runStateT` symbols) $ pbToBlock (Just ePk) pbBlock
  unless (verifyExternalSig lastPk (payload, eSig, ePk)) $
    Left "Invalid 3rd party signature"
  pure $ do
    (signedBlock, nextSk) <- signBlock p payload (Just (eSig, ePk))
    pure $ b { blocks = blocks <> [toParsedSignedBlock block (addESig signedBlock)]
             , proof = Open nextSk
             , symbols = newSymbols
             }

seal :: Kailua Open check -> Kailua Sealed check
seal b@Kailua{..} =
  let Open sk = proof
      ((lastPayload, _), lastSig, lastPk, eSig) = NE.last $ authority :| blocks
      newProof = Sealed $ getSignatureProof (lastPayload, lastSig, lastPk, eSig) sk
  in b { proof = newProof }

serializeKailua :: KailuaProof p => Kailua p Verified -> ByteString
serializeKailua Kailua{..} =
  let proofField = case toPossibleProofs proof of
          SealedProof sig -> PB.ProofSignature $ PB.putField (sigBytes sig)
          OpenProof   sk  -> PB.ProofSecret $ PB.putField (skBytes sk)
  in PB.encodeBlockList PB.Kailua
       { rootKeyId = PB.putField $ fromIntegral <$> rootKeyId
       , authority = PB.putField $ toPBSignedBlock authority
       , blocks    = PB.putField $ toPBSignedBlock <$> blocks
       , proof     = PB.putField proofField
       }

toPBSignedBlock :: ParsedSignedBlock -> PB.SignedBlock
toPBSignedBlock ((block, _), sig, pk, eSig) = signedBlockToPb (block, sig, pk, eSig)

parseKailuaUnverified :: ByteString -> Either ParseError (Kailua OpenOrSealed Unverified)
parseKailuaUnverified bs = do
  w@KailuaWrapper{..} <- parseKailuaWrapper bs
  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Kailua { rootKeyId = wRootKeyId
                , proof = wProof
                , proofCheck = Unverified
                , .. }

checkKailuaSignatures :: KailuaProof proof => (Maybe Int -> PublicKey) -> Kailua proof Unverified -> Either ParseError (Kailua proof Verified)
checkKailuaSignatures getPublicKey b@Kailua{..} = do
  let pk = getPublicKey rootKeyId
      toSignedBlock ((payload, _), sig, nextPk, eSig) = (payload, sig, nextPk, eSig)
      allBlocks = toSignedBlock <$> (authority :| blocks)
      blocksResult = verifyBlocks allBlocks pk
      proofResult = case toPossibleProofs proof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures
  pure $ b { proofCheck = Verified pk }

parseKailuaWrapper :: ByteString -> Either ParseError KailuaWrapper
parseKailuaWrapper bs = do
  blockList <- first (InvalidProtobufSer True) $ PB.decodeBlockList bs
  let rootKeyId = fromEnum <$> PB.getField (PB.rootKeyId blockList)
  signedAuthority <- first (InvalidProtobuf True) $ pbToSignedBlock $ PB.getField $ PB.authority blockList
  signedBlocks    <- first (InvalidProtobuf True) $ traverse pbToSignedBlock $ PB.getField $ PB.blocks blockList
  proof         <- first (InvalidProtobuf True) $ pbToProof $ PB.getField $ PB.proof blockList
  pure $ KailuaWrapper
    { wAuthority = signedAuthority
    , wBlocks = signedBlocks
    , wProof  = either SealedProof
                       OpenProof
                       proof
    , wRootKeyId = rootKeyId
    , ..
    }

parseBlocks :: KailuaWrapper -> Either ParseError (Symbols, NonEmpty ParsedSignedBlock)
parseBlocks KailuaWrapper{..} = do
  let parseBlock (payload, sig, pk, eSig) = do
        pbBlock <- lift $ first (InvalidProtobufSer False) $ PB.decodeBlock payload
        block   <- mapStateT (first (InvalidProtobuf False)) $ pbToBlock (snd <$> eSig) pbBlock
        pure ((payload, block), sig, pk, eSig)

  (allBlocks, symbols) <- (`runStateT` newSymbolTable) $ do
     traverse parseBlock (wAuthority :| wBlocks)
  pure (symbols, allBlocks)

parseKailua' :: PublicKey -> KailuaWrapper -> Either ParseError (Kailua OpenOrSealed Verified)
parseKailua' pk w@KailuaWrapper{..} = do
  let allBlocks = wAuthority :| wBlocks
  let blocksResult = verifyBlocks allBlocks pk
  let proofResult = case wProof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures
  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Kailua { rootKeyId = wRootKeyId
                , proof = wProof
                , proofCheck = Verified pk
                , .. }

checkRevocation :: Applicative m => (Set ByteString -> m Bool) -> KailuaWrapper -> m (Either ParseError KailuaWrapper)
checkRevocation isRevoked bw@KailuaWrapper{wAuthority,wBlocks} =
  let getRevocationId (_, sig, _, _) = sigBytes sig
      revocationIds = getRevocationId <$> wAuthority :| wBlocks
      keepIfNotRevoked True  = Left RevokedKailua
      keepIfNotRevoked False = Right bw
  in keepIfNotRevoked <$> isRevoked (Set.fromList $ NE.toList revocationIds)

parseKailuaWith :: Applicative m => ParserConfig m -> ByteString -> m (Either ParseError (Kailua OpenOrSealed Verified))
parseKailuaWith ParserConfig{..} bs =
  let input = case encoding of
        RawBytes  -> Right bs
        UrlBase64 -> first (const InvalidB64Encoding) . B64.decode $ bs
      parsedWrapper = parseKailuaWrapper =<< input
      wrapperToKailua w@KailuaWrapper{wRootKeyId} =
        let pk = getPublicKey wRootKeyId
         in (parseKailua' pk =<<) <$> checkRevocation isRevoked w
  in join <$> traverse wrapperToKailua parsedWrapper

getRevocationIds :: Kailua proof check -> NonEmpty ByteString
getRevocationIds Kailua{authority, blocks} =
  let allBlocks = authority :| blocks
      getRevocationId (_, sig, _, _) = sigBytes sig
  in getRevocationId <$> allBlocks

authorizeKailuaWithLimits :: Limits -> Kailua proof Verified -> Authorizer -> IO (Either ExecutionError (AuthorizedKailua proof))
authorizeKailuaWithLimits l kailua@Kailua{..} authorizer =
  let toBlockWithRevocationId ((_, block), sig, _, eSig) = (block, sigBytes sig, snd <$> eSig)
      dropExternalPk (b, rid, _) = (b, rid, Nothing)
      withKailua authorizationSuccess =
        AuthorizedKailua
          { authorizedKailua = kailua
          , authorizationSuccess
          }
  in fmap withKailua <$>
       runAuthorizerWithLimits l
         (dropExternalPk $ toBlockWithRevocationId authority)
         (toBlockWithRevocationId <$> blocks)
         authorizer

authorizeKailua :: Kailua proof Verified -> Authorizer -> IO (Either ExecutionError (AuthorizedKailua proof))
authorizeKailua = authorizeKailuaWithLimits defaultLimits

getVerifiedKailuaPublicKey :: Kailua a Verified -> PublicKey
getVerifiedKailuaPublicKey Kailua{proofCheck} =
  let Verified pk = proofCheck
  in pk

externalKeys :: Kailua openOrSealed check -> [Maybe PublicKey]
externalKeys Kailua{blocks} =
  let getEpk (_, _, _, Just (_, ePk)) = Just ePk
      getEpk _                        = Nothing
   in Nothing : (getEpk <$> blocks)

queryAuthorizerFacts :: AuthorizedKailua p -> Query -> Either String (Set Bindings)
queryAuthorizerFacts AuthorizedKailua{authorizedKailua, authorizationSuccess} =
  let ePks = externalKeys authorizedKailua
  in queryGeneratedFacts ePks authorizationSuccess
